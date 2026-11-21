/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.eclipse.biscuit.token.builder.Utils.constrainedRule;
import static org.junit.jupiter.api.Assertions.*;

import biscuit.format.schema.Schema;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Error.Parser;
import org.eclipse.biscuit.token.builder.AuthorizerBuilder;
import org.eclipse.biscuit.token.builder.Term;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AuthorizerTest {
  final RunLimits runLimits = new RunLimits(500, 100, Duration.ofMillis(500));
  private SecureRandom rng;

  @BeforeEach
  public void setUp() throws Exception {
    byte[] seed = {0, 0, 0, 0};
    rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(seed);
  }

  @Test
  public void testAuthorizerPolicy() throws Parser {
    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    List<Policy> policies = authorizerBuilder.policies();
    authorizerBuilder.deny();
    assertEquals(1, policies.size());

    authorizerBuilder.addPolicy(
        new Policy(
            Arrays.asList(
                constrainedRule(
                    "deny",
                    new ArrayList<>(),
                    new ArrayList<>(),
                    Arrays.asList(new Term.Bool(true)))),
            Policy.Kind.DENY));
    assertEquals(2, policies.size());

    authorizerBuilder.addPolicy("deny if true");
    assertEquals(3, policies.size());
  }

  @Test
  public void testPuttingSomeFactsInBiscuitAndGettingThemBackOutAgain() throws Exception {
    KeyPair keypair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Biscuit token =
        Biscuit.builder(keypair)
            .addAuthorityFact("email(\"bob@example.com\")")
            .addAuthorityFact("id(123)")
            .addAuthorityFact("enabled(true)")
            .addAuthorityFact("perms({1,2,3})")
            .build();

    Authorizer authorizer =
        Biscuit.fromBase64Url(token.serializeBase64Url(), keypair.getPublicKey())
            .verify(keypair.getPublicKey())
            .authorizer();

    Term emailTerm = queryFirstResult(authorizer, "emailfact($name) <- email($name)");
    assertEquals("bob@example.com", ((Term.Str) emailTerm).getValue());

    Term idTerm = queryFirstResult(authorizer, "idfact($name) <- id($name)");
    assertEquals(123, ((Term.Integer) idTerm).getValue());

    Term enabledTerm = queryFirstResult(authorizer, "enabledfact($name) <- enabled($name)");
    assertEquals(true, ((Term.Bool) enabledTerm).getValue());

    Term permsTerm = queryFirstResult(authorizer, "permsfact($name) <- perms($name)");
    assertEquals(
        Set.of(new Term.Integer(1), new Term.Integer(2), new Term.Integer(3)),
        ((Term.Set) permsTerm).getValue());
  }

  @Test
  public void eliminateUnusedBodyPredicateInRule() throws Exception {

    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    var block = Biscuit.builder(keyPair);
    for (int i = 0; i < 100; i++) {
      block.addAuthorityFact("f(" + i + ")");
    }

    block.addAuthorityRule("b($0) <- f($0), f($1), f($2), f($3), f($4), f($5)");

    var token = block.build();

    Authorizer authorizer =
        new AuthorizerBuilder()
            .addPolicy("allow if true")
            .build(
                Biscuit.fromBase64Url(token.serializeBase64Url(), keyPair.getPublicKey())
                    .verify(keyPair.getPublicKey()));

    RunLimits limits = new RunLimits(1_000_000_000, 1_000_000_000, Duration.ofDays(20), 1000);
    assertEquals(6, authorizer.getRules().stream().findFirst().get().body().size());

    assertThrows(Error.TooManySteps.class, () -> authorizer.authorize(limits));
  }

  @Test
  public void testDatalogAuthorizer() throws Exception {
    KeyPair keypair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Biscuit token =
        Biscuit.builder(keypair)
            .addAuthorityFact("email(\"bob@example.com\")")
            .addAuthorityFact("id(123)")
            .addAuthorityFact("enabled(true)")
            .addAuthorityFact("perms({1,2,3})")
            .build();

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();

    String l0 = "right($email) <- email($email)";
    String l1 = "check if right(\"bob@example.com\")";
    String l2 = "allow if true";
    String datalog = String.join(";", Arrays.asList(l0, l1, l2));
    authorizerBuilder.addDatalog(datalog);
    Authorizer authorizer =
        authorizerBuilder.build(
            Biscuit.fromBase64Url(token.serializeBase64Url(), keypair.getPublicKey())
                .verify(keypair.getPublicKey()));

    assertDoesNotThrow(() -> authorizer.authorize(runLimits));

    Term emailTerm = queryFirstResult(authorizer, "right($address) <- email($address)");
    assertEquals("bob@example.com", ((Term.Str) emailTerm).getValue());
  }

  @Test
  public void mergeCombinesBuilders() throws Exception {
    AuthorizerBuilder facts = new AuthorizerBuilder().addFact("resource(\"file1\")");
    AuthorizerBuilder policies =
        new AuthorizerBuilder().addCheck("check if resource(\"file1\")").allow();

    Authorizer authorizer =
        new AuthorizerBuilder().merge(facts).merge(policies).buildUnauthenticated();

    assertEquals(0, authorizer.authorize());
    assertEquals(1, facts.facts().size());
    assertEquals(0, facts.policies().size());
  }

  @Test
  public void mergeBlockAddsTheBlockContents() throws Exception {
    org.eclipse.biscuit.token.builder.Block block = new org.eclipse.biscuit.token.builder.Block();
    block.addFact("resource(\"file1\")");
    block.addRule("allowed($r) <- resource($r)");
    block.addCheck("check if allowed(\"file1\")");

    Authorizer authorizer =
        new AuthorizerBuilder().mergeBlock(block).allow().buildUnauthenticated();

    assertEquals(0, authorizer.authorize());
  }

  @Test
  public void builderPrintsItsDatalog() throws Exception {
    AuthorizerBuilder builder =
        new AuthorizerBuilder()
            .addFact("resource(\"file1\")")
            .addRule("allowed($r) <- resource($r)")
            .addCheck("check if allowed(\"file1\")")
            .addPolicy("allow if true");

    assertEquals(
        "resource(\"file1\");\n\n"
            + "allowed($r) <- resource($r);\n\n"
            + "check if allowed(\"file1\");\n\n"
            + "allow if true;\n",
        builder.toString());
  }

  @Test
  public void resourceAndOperationHelpers() throws Exception {
    AuthorizerBuilder builder =
        new AuthorizerBuilder()
            .addResource("file1")
            .addOperation("read")
            .checkResource("file1")
            .checkOperation("read")
            .allow();
    assertEquals(0, builder.buildUnauthenticated().authorize());

    Authorizer wrongOperation =
        new AuthorizerBuilder()
            .addResource("file1")
            .addOperation("write")
            .checkOperation("read")
            .allow()
            .buildUnauthenticated();
    assertThrows(Error.FailedLogic.class, wrongOperation::authorize);
  }

  @Test
  public void resourcePrefixAndSuffixHelpers() throws Exception {
    Authorizer matching =
        new AuthorizerBuilder()
            .addResource("/folder/file.txt")
            .resourcePrefix("/folder/")
            .resourceSuffix(".txt")
            .allow()
            .buildUnauthenticated();
    assertEquals(0, matching.authorize());

    Authorizer wrongPrefix =
        new AuthorizerBuilder()
            .addResource("/other/file.txt")
            .resourcePrefix("/folder/")
            .allow()
            .buildUnauthenticated();
    assertThrows(Error.FailedLogic.class, wrongPrefix::authorize);
  }

  @Test
  public void expirationDateHelper() throws Exception {
    Date future = new Date(System.currentTimeMillis() + 3_600_000);
    Date past = new Date(System.currentTimeMillis() - 3_600_000);

    Authorizer valid =
        new AuthorizerBuilder().setTime().setExpirationDate(future).allow().buildUnauthenticated();
    assertEquals(0, valid.authorize());

    Authorizer expired =
        new AuthorizerBuilder().setTime().setExpirationDate(past).allow().buildUnauthenticated();
    assertThrows(Error.FailedLogic.class, expired::authorize);
  }

  private static Term queryFirstResult(Authorizer authorizer, String query) throws Error {
    return authorizer.query(query).iterator().next().terms().get(0);
  }
}
