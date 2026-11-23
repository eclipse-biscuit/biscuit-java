/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import biscuit.format.schema.Schema;
import java.security.SecureRandom;
import java.time.Duration;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.AuthorizerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@code maxSteps} limit.
 *
 * <p>The budgets below come from how the steps are counted today: one step per candidate fact
 * pulled for a body predicate, and one step per operator applied in an expression. The comments
 * give the cost each scenario is expected to have.
 */
public class StepLimitTest {
  private static final String TWENTY =
      "0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19";
  private static final String TEN = "0, 1, 2, 3, 4, 5, 6, 7, 8, 9";

  private SecureRandom rng;

  /** Limits where only maxSteps can realistically trip. */
  private static RunLimits steps(long maxSteps) {
    return new RunLimits(1_000_000, 1_000_000, Duration.ofDays(1), maxSteps);
  }

  @BeforeEach
  public void setUp() throws Exception {
    byte[] seed = {0, 0, 0, 0};
    rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(seed);
  }

  // ---------------------------------------------------------------------------------------------
  // Fact identification
  // ---------------------------------------------------------------------------------------------

  @Test
  public void joinOverBudgetThrowsTooManySteps() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 10; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("b($0) <- f($0), f($1), f($2), f($3)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(1000)));
  }

  @Test
  public void smallJoinWithinBudgetAuthorizes() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 5; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("b($0) <- f($0), f($1)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertDoesNotThrow(() -> authorizer.authorize(steps(1000)));
  }

  @Test
  public void exactBudgetAuthorizes() throws Exception {
    // 5 facts, one predicate: 5 candidates per pass, two passes (the second finds nothing new)
    // = exactly 10 steps. Using the whole budget is not exceeding it.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 5; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("b($0) <- f($0)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertDoesNotThrow(() -> authorizer.authorize(steps(10)));
  }

  @Test
  public void oneStepUnderBudgetThrowsTooManySteps() throws Exception {
    // generates 5 new facts, then does another pass to check if there are more facts to generate
    // and then trips runtime detection
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 5; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("b($0) <- f($0)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(9)));
  }

  @Test
  public void zeroBudgetWithNothingToDoAuthorizes() throws Exception {
    Authorizer authorizer =
        new AuthorizerBuilder().addPolicy("allow if true").buildUnauthenticated();

    assertDoesNotThrow(() -> authorizer.authorize(steps(0)));
  }

  @Test
  public void zeroBudgetWithFactsToScanThrowsTooManySteps() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("f(1)");
    block.addAuthorityRule("b($0) <- f($0)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(0)));
  }

  @Test
  public void budgetIsSharedAcrossRules() throws Exception {
    // Each rule costs 10 steps on its own and fits in 15. Together they cost 20 because we
    // retrigger to see if there are more facts to generate.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 5; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("b($0) <- f($0)");
    block.addAuthorityRule("c($0) <- f($0)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(15)));
  }

  @Test
  public void stepLimitDoesNotHideTooManyFacts() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 20; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("g($0) <- f($0)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    RunLimits limits = new RunLimits(10, 1_000_000, Duration.ofDays(1), 1_000_000);
    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManyFacts.class, () -> authorizer.authorize(limits));
  }

  @Test
  public void explicitLimitsGiveEachAuthorizationAFullBudget() throws Exception {
    // The check visits the 8 facts and compares each one: 16 steps per authorization. 16 + 16
    // would not fit in 20, so this only passes if the second call gets 20 steps on top of the ones
    // already taken.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 8; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }

    Authorizer authorizer =
        new AuthorizerBuilder()
            .addCheck("check all f($0), $0 >= 0")
            .addPolicy("allow if true")
            .build(block.build());

    assertDoesNotThrow(() -> authorizer.authorize(steps(20)));
    assertDoesNotThrow(() -> authorizer.authorize(steps(20)));
  }

  @Test
  public void authorizerLimitsCountTheStepsAlreadyTaken() throws Exception {
    // The first call takes 1001 steps: 1000 for the evaluation (500 facts, two passes) and 1 for
    // the check. That is more than the authorizer's 1000 steps, so the second call fails on its
    // first step.
    Authorizer authorizer = authorizerBudgetTaken();

    assertDoesNotThrow(() -> authorizer.authorize(steps(1001)));
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize());
  }

  @Test
  public void queryWithAuthorizerLimitsCountsTheStepsTakenByAuthorize() throws Exception {
    Authorizer authorizer = authorizerBudgetTaken();

    assertDoesNotThrow(() -> authorizer.authorize(steps(1001)));
    assertThrows(Error.TooManySteps.class, () -> authorizer.query("q($0) <- b($0)"));
  }

  @Test
  public void clonedAuthorizerKeepsTheStepsTaken() throws Exception {
    Authorizer authorizer = authorizerBudgetTaken();

    assertDoesNotThrow(() -> authorizer.authorize(steps(1001)));
    Authorizer cloned = authorizer.clone();
    assertThrows(Error.TooManySteps.class, () -> cloned.authorize());
  }

  @Test
  public void maximumBudgetDoesNotOverflowAfterStepsWereTaken() throws Exception {
    Authorizer authorizer = authorizerBudgetTaken();

    assertDoesNotThrow(() -> authorizer.authorize(steps(Long.MAX_VALUE)));
    assertDoesNotThrow(() -> authorizer.authorize(steps(Long.MAX_VALUE)));
  }

  @Test
  public void evaluationRunsOnlyOnce() throws Exception {
    // Running the evaluation again would take 500 steps, the check alone takes 1.
    Authorizer authorizer = authorizerBudgetTaken();

    assertDoesNotThrow(() -> authorizer.authorize(steps(1001)));
    assertDoesNotThrow(() -> authorizer.authorize(steps(1)));
    assertEquals(1002, authorizer.elapsedSteps());
  }

  @Test
  public void buildDoesNotRunTheEvaluation() throws Exception {
    AuthorizerBuilder builder = new AuthorizerBuilder().addPolicy("allow if true");
    builder.setLimits(steps(10));
    Authorizer authorizer = builder.build(fiveHundredFacts());

    assertTrue(authorizer.executionTime().isEmpty());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize());
  }

  private Biscuit fiveHundredFacts() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 500; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("b($0) <- f($0)");
    return block.build();
  }

  private Authorizer authorizerBudgetTaken() throws Exception {
    return new AuthorizerBuilder()
        .addCheck("check if 1 == 1")
        .addPolicy("allow if true")
        .setLimits(steps(1000))
        .build(fiveHundredFacts());
  }

  // ---------------------------------------------------------------------------------------------
  // Expression evaluation
  // ---------------------------------------------------------------------------------------------

  @Test
  public void anyWithoutAMatchVisitsEveryElement() throws Exception {
    // 1 fact + 1 any + 20 * (1 call + 1 comparison) = 42 steps, which does not fit in 20.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");
    block.addAuthorityRule("ok(1) <- x($0), $0.any($1 -> $1 == -1)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(40)));
  }

  @Test
  public void anyStopsCountingAtTheFirstMatch() throws Exception {
    // The first element matches: 1 fact + 1 any + (1 call + 1 comparison) = 4 steps per pass,
    // two passes.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");
    block.addAuthorityRule("ok(1) <- x($0), $0.any($1 -> $1 == 0)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertDoesNotThrow(() -> authorizer.authorize(steps(8)));
  }

  @Test
  public void allStopsCountingAtTheFirstFailure() throws Exception {
    // The first element fails the test: 1 fact + 1 all + (1 call + 1 comparison) = 4 steps.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([100, " + TWENTY + "])");
    block.addAuthorityRule("ok(1) <- x($0), $0.all($1 -> $1 < 50)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Biscuit token = block.build();
    Authorizer authorizer = authorizerBuilder.build(token);
    Authorizer tooSmall = authorizerBuilder.build(token);
    assertDoesNotThrow(() -> authorizer.authorize(steps(4)));
    assertThrows(Error.TooManySteps.class, () -> tooSmall.authorize(steps(3)));
  }

  @Test
  public void allVisitsEveryElementWhenTheyAllPass() throws Exception {
    // The failing element is last, so all 21 elements are visited: 1 + 1 + 21 * 2 = 44 steps.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + ", 100])");
    block.addAuthorityRule("ok(1) <- x($0), $0.all($1 -> $1 < 50)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(43)));
    assertDoesNotThrow(() -> authorizer.authorize(steps(44)));
  }

  @Test
  public void lightClosureBodyFitsTheBudget() throws Exception {
    // 1 fact + 1 any + 20 * (1 call + 1 operator) = 42 steps
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");
    block.addAuthorityRule("ok(1) <- x($0), $0.any($1 -> $1 == -1)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertDoesNotThrow(() -> authorizer.authorize(steps(42)));
  }

  @Test
  public void everyOperatorInsideAClosureCounts() throws Exception {
    // Same shape as above, but the body applies five operators per element:
    // 1 fact + 1 any + 20 * (1 call + 5 operators) = 122 steps, which does not fit in 50.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");
    block.addAuthorityRule("ok(1) <- x($0), $0.any($1 -> $1 + 1 + 1 + 1 + 1 == -1)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(50)));
  }

  @Test
  public void applyingAnyToEachElementCountsEvenWithoutOperators() throws Exception {
    // The closure body is a constant, so there are no operators inside it, but any is still
    // applied to each of the 20 elements.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");
    block.addAuthorityRule("ok(1) <- x($0), $0.any($1 -> false)");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(10)));
  }

  @Test
  public void nestedAnyOverTenElementsFitsTheDefaultBudget() throws Exception {
    // two levels over 10 elements: about 100 comparisons
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TEN + "])");
    block.addAuthorityRule("ok(1) <- x($0), $0.any($1 -> $0.any($2 -> $2 == 999))");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertDoesNotThrow(() -> authorizer.authorize(steps(new RunLimits().getMaxSteps())));
  }

  @Test
  public void deeplyNestedAnyExceedsTheDefaultBudget() throws Exception {
    // The example from the spec: 10 elements nested 4 deep is 10^4 evaluations of a tiny
    // expression, far more than the default 1000 steps.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TEN + "])");
    block.addAuthorityRule(
        "ok(1) <- x($0), $0.any($1 -> $0.any($2 -> $0.any($3 -> $0.any($4 -> $4 == 999))))");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(
        Error.TooManySteps.class, () -> authorizer.authorize(steps(new RunLimits().getMaxSteps())));
  }

  // ---------------------------------------------------------------------------------------------
  // Running out of steps inside a check
  //
  // Each of these needs about 42 steps, so a budget of 10 runs out in the middle of the
  // expression. That must be reported as TooManySteps, not as an ordinary check failure.
  // ---------------------------------------------------------------------------------------------

  @Test
  public void exhaustionInsideACheckIsReportedAsTooManySteps() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addCheck("check if x($a), $a.any($e -> $e == 19)");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(10)));
  }

  @Test
  public void exhaustionInsideARejectCheckDoesNotLetAuthorizationThrough() throws Exception {
    // With enough steps the element is found and the reject check denies the request.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addCheck("reject if x($a), $a.any($e -> $e == 19)");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(10)));
  }

  @Test
  public void tryOrDoesNotSwallowStepExhaustion() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addCheck("reject if x($a), ($a.any($e -> $e == 19)).try_or(false)");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(10)));
  }

  @Test
  public void findMatchDoesNotSwallowExhaustion() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addCheck("reject if ([" + TWENTY + "].any($e -> $e == 19)).try_or(false)");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(10)));
  }

  @Test
  public void checkMatchAllDoesNotSwallowExhaustion() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addCheck("check all ([" + TWENTY + "].any($e -> $e == 19)).try_or(true)");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertDoesNotThrow(() -> authorizer.authorize(steps(1_000)));
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(10)));
  }

  @Test
  public void checkAllDoesNotPassWhenIterationIsCutShort() throws Exception {
    // One step per candidate fact and no expressions, so with 10 facts and a budget of 3 the
    // combinator stops after the third fact and the loop ends as if there were no more matches.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 10; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addCheck("check all f($a)");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertDoesNotThrow(() -> authorizer.authorize(steps(1_000)));
    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(steps(3)));
  }

  @Test
  public void rejectCheckDeniesWhenThereAreEnoughSteps() throws Exception {
    // Control for the two tests above: same token and check, ample budget.
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    block.addAuthorityFact("x([" + TWENTY + "])");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addCheck("reject if x($a), $a.any($e -> $e == 19)");
    authorizerBuilder.addCheck("reject if ([" + TWENTY + "].any($e -> $e == 19)).try_or(false)");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(block.build());
    assertThrows(Error.FailedLogic.class, () -> authorizer.authorize(steps(1_000)));
  }

  @Test
  public void expressionOnlyChecksCountTowardTheBudget() throws Exception {
    // Each check costs 1 any + 20 * (1 call + 1 comparison) = 41 steps.
    AuthorizerBuilder oneCheckBuilder =
        new AuthorizerBuilder()
            .addCheck("check if [" + TWENTY + "].any($e -> $e == 19)")
            .addPolicy("allow if true");
    Authorizer oneCheck = oneCheckBuilder.buildUnauthenticated();
    Authorizer oneCheckUnderBudget = oneCheckBuilder.buildUnauthenticated();

    // The checks share one budget: 41 + 41 = 82 steps.
    Authorizer twoChecks =
        new AuthorizerBuilder()
            .addCheck("check if [" + TWENTY + "].any($e -> $e == 19)")
            .addCheck("check if [" + TWENTY + "].any($e -> $e == 19)")
            .addPolicy("allow if true")
            .buildUnauthenticated();

    assertDoesNotThrow(() -> oneCheck.authorize(steps(41)));
    assertThrows(Error.TooManySteps.class, () -> oneCheckUnderBudget.authorize(steps(40)));
    assertThrows(Error.TooManySteps.class, () -> twoChecks.authorize(steps(81)));
  }

  // Authorizer.query (World.queryRule)
  private Authorizer authorizerWithTenFacts() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 10; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    return block.build().authorizer();
  }

  @Test
  public void queryReportsExhaustionWhenIterationIsCutShort() throws Exception {
    // One step per candidate fact and no expressions: 10 facts = 10 steps. When the budget runs
    // out the combinator just stops, so queryRule has to notice that the counter ran out instead
    // of returning the facts it saw so far.
    Authorizer authorizer = authorizerWithTenFacts();

    assertEquals(10, authorizer.query("r($a) <- f($a)", steps(10)).size());
    assertThrows(Error.TooManySteps.class, () -> authorizer.query("r($a) <- f($a)", steps(9)));
    assertThrows(Error.TooManySteps.class, () -> authorizer.query("r($a) <- f($a)", steps(3)));
  }

  @Test
  public void queryReportsErrorsFromExpressions() throws Exception {
    Authorizer authorizer = authorizerWithTenFacts();
    String comparison = "r($a) <- f($a), $a >= 0";
    String tryOr = "r($a) <- f($a), ([" + TWENTY + "].any($e -> $e == 19)).try_or(true)";

    assertEquals(10, authorizer.query(comparison, steps(1_000)).size());
    assertEquals(10, authorizer.query(tryOr, steps(1_000)).size());

    // 1 step per fact plus 1 for the comparison, so 5 runs out inside an expression. try_or must
    // not turn that into its fallback.
    assertThrows(Error.TooManySteps.class, () -> authorizer.query(comparison, steps(5)));
    assertThrows(Error.TooManySteps.class, () -> authorizer.query(tryOr, steps(10)));

    // A non-boolean result is an error, not a dropped match.
    assertThrows(Error.InvalidType.class, () -> authorizer.query("r($a) <- f($a), $a + 1"));
  }

  private Authorizer authorizerWithDerivedFacts() throws Exception {
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 10; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }
    block.addAuthorityRule("g($a) <- f($a)");
    return block.build().authorizer();
  }

  @Test
  public void queryUsesWhatIsLeftOfTheBudgetAfterTheRun() throws Exception {
    Authorizer fits = authorizerWithDerivedFacts();
    Authorizer doesNotFit = authorizerWithDerivedFacts();

    assertEquals(10, fits.query("r($a) <- g($a)", steps(30)).size());
    assertThrows(Error.TooManySteps.class, () -> doesNotFit.query("r($a) <- g($a)", steps(25)));
  }
}
