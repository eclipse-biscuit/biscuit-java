/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.eclipse.biscuit.datalog.Check.Kind.REJECT;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.*;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.FailedCheck;
import org.eclipse.biscuit.error.LogicError;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.builder.AuthorizerBuilder;
import org.eclipse.biscuit.token.builder.Check;
import org.eclipse.biscuit.token.builder.Fact;
import org.eclipse.biscuit.token.builder.Rule;
import org.eclipse.biscuit.token.builder.Term;
import org.eclipse.biscuit.token.builder.Utils;
import org.eclipse.biscuit.token.builder.parser.Parser;

/** Token verification class */
public final class Authorizer {
  private final Biscuit token;
  private final List<Check> checks;
  private final List<Policy> policies;
  private final List<Scope> scopes;
  private final HashMap<Long, List<Long>> publicKeyToBlockId;
  private final World world;
  private final SymbolTable symbolTable;
  private final StepCounter steps;
  private final RunLimits limits;
  private Duration executionTime;

  private Authorizer(
      Biscuit token,
      List<Check> checks,
      List<Policy> policies,
      List<Scope> scopes,
      HashMap<Long, List<Long>> publicKeyToBlockId,
      World world,
      SymbolTable symbolTable,
      StepCounter steps,
      RunLimits limits,
      Duration executionTime) {
    this.token = token;
    this.checks = checks;
    this.policies = policies;
    this.scopes = scopes;
    this.publicKeyToBlockId = publicKeyToBlockId;
    this.world = world;
    this.symbolTable = symbolTable;
    this.steps = steps;
    this.limits = limits;
    this.executionTime = executionTime;
  }

  /**
   * Creates an authorizer from the contents of a builder, for a token or without one
   *
   * <p>the Datalog evaluation is not run here, but on the first call to {@code authorize} or
   * {@code query}
   */
  public static Authorizer make(AuthorizerBuilder builder, Biscuit token) throws Error.FailedLogic {
    SymbolTable symbolTable =
        token != null ? new SymbolTable(token.symbolTable) : Biscuit.defaultSymbolTable();
    Authorizer authorizer =
        new Authorizer(
            token,
            new ArrayList<>(builder.checks()),
            new ArrayList<>(builder.policies()),
            new ArrayList<>(),
            new HashMap<>(),
            new World(),
            symbolTable,
            new StepCounter(),
            builder.limits(),
            null);
    authorizer.loadToken();

    for (org.eclipse.biscuit.token.builder.Scope scope : builder.scopes()) {
      authorizer.scopes.add(scope.convert(symbolTable));
    }
    for (Fact fact : builder.facts()) {
      authorizer.world.addFact(Origin.authorizer(), fact.convert(symbolTable));
    }
    TrustedOrigins authorizerTrustedOrigins = authorizer.authorizerTrustedOrigins();
    for (Rule rule : builder.rules()) {
      org.eclipse.biscuit.datalog.Rule r = rule.convert(symbolTable);
      TrustedOrigins ruleTrustedOrigins =
          TrustedOrigins.fromScopes(
              r.scopes(), authorizerTrustedOrigins, Long.MAX_VALUE, authorizer.publicKeyToBlockId);
      authorizer.world.addRule(Long.MAX_VALUE, ruleTrustedOrigins, r);
    }

    return authorizer;
  }

  public Authorizer clone() {
    HashMap<Long, List<Long>> publicKeyToBlockId = new HashMap<>();
    for (Map.Entry<Long, List<Long>> entry : this.publicKeyToBlockId.entrySet()) {
      publicKeyToBlockId.put(entry.getKey(), new ArrayList<>(entry.getValue()));
    }
    return new Authorizer(
        this.token,
        new ArrayList<>(this.checks),
        new ArrayList<>(this.policies),
        new ArrayList<>(this.scopes),
        publicKeyToBlockId,
        new World(this.world),
        new SymbolTable(this.symbolTable),
        new StepCounter(this.steps.taken()),
        this.limits,
        this.executionTime);
  }

  private void loadToken() throws Error.FailedLogic {
    if (token != null) {
      for (long i = 0; i < token.blocks.size(); i++) {
        Block block = token.blocks.get((int) i);

        if (block.getExternalKey().isPresent()) {
          PublicKey pk = block.getExternalKey().get();
          long newKeyId = this.symbolTable.insert(pk);
          if (!this.publicKeyToBlockId.containsKey(newKeyId)) {
            List<Long> l = new ArrayList<>();
            l.add(i + 1);
            this.publicKeyToBlockId.put(newKeyId, l);
          } else {
            this.publicKeyToBlockId.get(newKeyId).add(i + 1);
          }
        }
      }

      TrustedOrigins authorityTrustedOrigins =
          TrustedOrigins.fromScopes(
              token.authority.getScopes(),
              TrustedOrigins.defaultOrigins(),
              0,
              this.publicKeyToBlockId);

      for (org.eclipse.biscuit.datalog.Fact fact : token.authority.getFacts()) {
        org.eclipse.biscuit.datalog.Fact convertedFact =
            Fact.convertFrom(fact, token.symbolTable).convert(this.symbolTable);
        world.addFact(new Origin(0), convertedFact);
      }
      for (org.eclipse.biscuit.datalog.Rule rule : token.authority.getRules()) {
        Rule locRule = Rule.convertFrom(rule, token.symbolTable);
        org.eclipse.biscuit.datalog.Rule convertedRule = locRule.convert(this.symbolTable);

        var res = locRule.validateVariables();
        if (res.isErr()) {
          throw new Error.FailedLogic(
              new LogicError.InvalidBlockRule(0, token.symbolTable.formatRule(convertedRule)));
        }
        TrustedOrigins ruleTrustedOrigins =
            TrustedOrigins.fromScopes(
                convertedRule.scopes(), authorityTrustedOrigins, 0, this.publicKeyToBlockId);
        world.addRule((long) 0, ruleTrustedOrigins, convertedRule);
      }

      for (long i = 0; i < token.blocks.size(); i++) {
        Block block = token.blocks.get((int) i);
        SymbolTable blockSymbolTable = token.symbolTable;
        if (block.getExternalKey().isPresent()) {
          blockSymbolTable = new SymbolTable(block.getSymbolTable(), block.getPublicKeys());
        }
        TrustedOrigins blockTrustedOrigins =
            TrustedOrigins.fromScopes(
                translateBlockScopes(i + 1, block.getScopes(), blockSymbolTable),
                TrustedOrigins.defaultOrigins(),
                i + 1,
                this.publicKeyToBlockId);

        for (org.eclipse.biscuit.datalog.Fact fact : block.getFacts()) {
          org.eclipse.biscuit.datalog.Fact convertedFact =
              Fact.convertFrom(fact, blockSymbolTable).convert(this.symbolTable);
          world.addFact(new Origin(i + 1), convertedFact);
        }

        for (org.eclipse.biscuit.datalog.Rule rule : block.getRules()) {
          Rule syRole = Rule.convertFrom(rule, blockSymbolTable);
          org.eclipse.biscuit.datalog.Rule convertedRule = syRole.convert(this.symbolTable);

          var res = syRole.validateVariables();
          if (res.isErr()) {
            throw new Error.FailedLogic(
                new LogicError.InvalidBlockRule(0, this.symbolTable.formatRule(convertedRule)));
          }
          TrustedOrigins ruleTrustedOrigins =
              TrustedOrigins.fromScopes(
                  convertedRule.scopes(), blockTrustedOrigins, i + 1, this.publicKeyToBlockId);
          world.addRule(i + 1, ruleTrustedOrigins, convertedRule);
        }
      }
    }
  }

  private List<Scope> translateBlockScopes(
      long blockId, List<Scope> scopes, SymbolTable blockSymbolTable) throws Error.FailedLogic {
    List<Scope> translated = new ArrayList<>(scopes.size());
    for (Scope scope : scopes) {
      // builder.Scope.convertFrom narrows the index to an int and assumes the key exists, so
      // reject anything out of range here rather than let it wrap around or throw unchecked
      if (scope.kind() == Scope.Kind.PublicKey) {
        long index = scope.getPublicKey();
        if (index < 0 || index >= blockSymbolTable.getPublicKeys().size()) {
          throw new Error.FailedLogic(
              new LogicError.InvalidBlockScope(blockId, "unknown public key index " + index));
        }
      }
      translated.add(
          org.eclipse.biscuit.token.builder.Scope.convertFrom(scope, blockSymbolTable)
              .convert(this.symbolTable));
    }
    return translated;
  }

  /** Runs the Datalog evaluation with the authorizer's limits, if it has not run yet */
  public Duration run() throws Error {
    return this.run(this.limitsWithMaxSteps(this.remainingSteps()));
  }

  /** Runs the Datalog evaluation with the given limits, if it has not run yet */
  public Duration run(RunLimits limits) throws Error {
    long maxSteps = this.maxSteps(limits);
    if (this.executionTime != null) {
      return this.executionTime;
    }
    Instant start = Instant.now();
    this.world.run(limits, this.steps.budget(maxSteps), this.symbolTable);
    this.executionTime = Duration.between(start, Instant.now());
    return this.executionTime;
  }

  /** The limits of the authorizer, minus what was already used by previous calls */
  private RunLimits remainingLimits(Duration executionTime) throws Error.Timeout {
    if (executionTime.compareTo(this.limits.getMaxTime()) >= 0) {
      throw new Error.Timeout();
    }
    return new RunLimits(
        this.limits.getMaxFacts(),
        this.limits.getMaxIterations() - this.world.iterations(),
        this.limits.getMaxTime().minus(executionTime),
        this.remainingSteps());
  }

  private RunLimits limitsWithMaxSteps(long maxSteps) {
    return new RunLimits(
        this.limits.getMaxFacts(),
        this.limits.getMaxIterations(),
        this.limits.getMaxTime(),
        maxSteps);
  }

  private long remainingSteps() {
    return Math.max(0, this.limits.getMaxSteps() - this.steps.taken());
  }

  /** Total step count the authorizer can reach in a call using {@code limits} */
  private long maxSteps(RunLimits limits) {
    long taken = this.steps.taken();
    long maxSteps = limits.getMaxSteps();
    return maxSteps > Long.MAX_VALUE - taken ? Long.MAX_VALUE : taken + maxSteps;
  }

  public TrustedOrigins authorizerTrustedOrigins() {
    return TrustedOrigins.fromScopes(
        this.scopes, TrustedOrigins.defaultOrigins(), Long.MAX_VALUE, this.publicKeyToBlockId);
  }

  public List<String> getRevocationIds() throws Error {
    ArrayList<String> ids = new ArrayList<>();

    final Rule getRevocationIds =
        Utils.rule(
            "revocation_id",
            List.of(Utils.var("id")),
            List.of(Utils.pred("revocation_id", List.of(Utils.var("id")))));

    this.query(getRevocationIds).stream()
        .forEach(
            fact -> {
              fact.terms().stream()
                  .forEach(
                      id -> {
                        if (id instanceof Term.Str) {
                          ids.add(((Term.Str) id).getValue());
                        }
                      });
            });

    return ids;
  }

  public Set<Fact> query(Rule query) throws Error {
    Duration executionTime = this.run();
    return this.query(query, this.remainingLimits(executionTime));
  }

  public Set<Fact> query(String s) throws Error {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return query(res.getOk()._2);
  }

  /** Runs a query, overriding the authorizer's limits for this call */
  public Set<Fact> query(Rule query, RunLimits limits) throws Error {
    long maxSteps = this.maxSteps(limits);
    Duration executionTime = this.run(limits);
    Instant start = Instant.now();
    try {
      return this.queryInner(query, maxSteps);
    } finally {
      this.executionTime = executionTime.plus(Duration.between(start, Instant.now()));
    }
  }

  public Set<Fact> query(String s, RunLimits limits) throws Error {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return query(res.getOk()._2, limits);
  }

  private Set<Fact> queryInner(Rule query, long maxSteps) throws Error {
    org.eclipse.biscuit.datalog.Rule rule = query.convert(symbolTable);
    TrustedOrigins ruleTrustedorigins =
        TrustedOrigins.fromScopes(
            rule.scopes(),
            TrustedOrigins.defaultOrigins(),
            Long.MAX_VALUE,
            this.publicKeyToBlockId);

    FactSet facts =
        world.queryRule(
            rule, Long.MAX_VALUE, ruleTrustedorigins, symbolTable, this.steps.budget(maxSteps));
    Set<Fact> s = new HashSet<>();

    for (Iterator<org.eclipse.biscuit.datalog.Fact> it = facts.stream().iterator();
        it.hasNext(); ) {
      org.eclipse.biscuit.datalog.Fact f = it.next();
      s.add(Fact.convertFrom(f, symbolTable));
    }

    return s;
  }

  public Long authorize() throws Error {
    Duration executionTime = this.run();
    return this.authorize(this.remainingLimits(executionTime));
  }

  /** Verifies the checks and policies, overriding the authorizer's limits for this call */
  public Long authorize(RunLimits limits) throws Error {
    long maxSteps = this.maxSteps(limits);
    Duration executionTime = this.run(limits);
    Instant start = Instant.now();
    try {
      return this.authorizeInner(limits, maxSteps);
    } finally {
      this.executionTime = executionTime.plus(Duration.between(start, Instant.now()));
    }
  }

  public Optional<Duration> executionTime() {
    return Optional.ofNullable(this.executionTime);
  }

  public int iterations() {
    return this.world.iterations();
  }

  public long elapsedSteps() {
    return this.steps.taken();
  }

  public RunLimits limits() {
    return this.limits;
  }

  private Long authorizeInner(RunLimits limits, long maxSteps) throws Error {
    StepBudget budget = this.steps.budget(maxSteps);
    Instant timeLimit = Instant.now().plus(limits.getMaxTime());
    List<FailedCheck> errors = new LinkedList<>();

    TrustedOrigins authorizerTrustedOrigins = this.authorizerTrustedOrigins();

    for (int i = 0; i < this.checks.size(); i++) {
      org.eclipse.biscuit.datalog.Check c = this.checks.get(i).convert(symbolTable);
      boolean successful = false;

      for (org.eclipse.biscuit.datalog.Rule query : c.queries()) {
        TrustedOrigins ruleTrustedOrigins =
            TrustedOrigins.fromScopes(
                query.scopes(), authorizerTrustedOrigins, Long.MAX_VALUE, this.publicKeyToBlockId);
        switch (c.kind()) {
          case ONE:
            successful =
                world.queryMatch(query, Long.MAX_VALUE, ruleTrustedOrigins, symbolTable, budget);
            break;
          case ALL:
            successful = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable, budget);
            break;
          case REJECT:
            successful =
                world.queryMatch(query, Long.MAX_VALUE, ruleTrustedOrigins, symbolTable, budget);
            break;
          default:
            throw new RuntimeException("unmapped kind");
        }

        if (Instant.now().compareTo(timeLimit) >= 0) {
          throw new Error.Timeout();
        }

        if (successful) {
          break;
        }
      }

      if (successful == (c.kind() == REJECT)) {
        errors.add(new FailedCheck.FailedAuthorizer(i, symbolTable.formatCheck(c)));
      }
    }

    if (token != null) {
      TrustedOrigins authorityTrustedOrigins =
          TrustedOrigins.fromScopes(
              token.authority.getScopes(),
              TrustedOrigins.defaultOrigins(),
              0,
              this.publicKeyToBlockId);

      for (int j = 0; j < token.authority.getChecks().size(); j++) {
        boolean successful = false;

        Check c = Check.convertFrom(token.authority.getChecks().get(j), token.symbolTable);
        org.eclipse.biscuit.datalog.Check check = c.convert(symbolTable);

        for (int k = 0; k < check.queries().size(); k++) {
          org.eclipse.biscuit.datalog.Rule query = check.queries().get(k);
          TrustedOrigins ruleTrustedOrigins =
              TrustedOrigins.fromScopes(
                  query.scopes(), authorityTrustedOrigins, 0, this.publicKeyToBlockId);
          switch (check.kind()) {
            case ONE:
              successful =
                  world.queryMatch(query, (long) 0, ruleTrustedOrigins, symbolTable, budget);
              break;
            case ALL:
              successful = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable, budget);
              break;
            case REJECT:
              successful =
                  world.queryMatch(query, (long) 0, ruleTrustedOrigins, symbolTable, budget);
              break;
            default:
              throw new RuntimeException("unmapped kind");
          }

          if (Instant.now().compareTo(timeLimit) >= 0) {
            throw new Error.Timeout();
          }

          if (successful) {
            break;
          }
        }

        if (successful == (c.kind() == REJECT)) {
          errors.add(new FailedCheck.FailedBlock(0, j, symbolTable.formatCheck(check)));
        }
      }
    }

    Optional<Result<Integer, Integer>> policyResult = Optional.empty();
    policies_test:
    for (int i = 0; i < this.policies.size(); i++) {
      Policy policy = this.policies.get(i);

      for (Rule policyQuery : policy.queries()) {
        org.eclipse.biscuit.datalog.Rule query = policyQuery.convert(symbolTable);
        TrustedOrigins policyTrustedOrigins =
            TrustedOrigins.fromScopes(
                query.scopes(), authorizerTrustedOrigins, Long.MAX_VALUE, this.publicKeyToBlockId);
        boolean res =
            world.queryMatch(query, Long.MAX_VALUE, policyTrustedOrigins, symbolTable, budget);

        if (Instant.now().compareTo(timeLimit) >= 0) {
          throw new Error.Timeout();
        }

        if (res) {
          if (policy.kind() == Policy.Kind.ALLOW) {
            policyResult = Optional.of(Result.ok(i));
          } else {
            policyResult = Optional.of(Result.err(i));
          }
          break policies_test;
        }
      }
    }

    if (token != null) {
      for (int i = 0; i < token.blocks.size(); i++) {
        Block b = token.blocks.get(i);
        SymbolTable blockSymbolTable = token.symbolTable;
        if (b.getExternalKey().isPresent()) {
          blockSymbolTable = new SymbolTable(b.getSymbolTable(), b.getPublicKeys());
        }
        TrustedOrigins blockTrustedOrigins =
            TrustedOrigins.fromScopes(
                translateBlockScopes(i + 1, b.getScopes(), blockSymbolTable),
                TrustedOrigins.defaultOrigins(),
                i + 1,
                this.publicKeyToBlockId);

        for (int j = 0; j < b.getChecks().size(); j++) {
          boolean successful = false;

          Check c = Check.convertFrom(b.getChecks().get(j), blockSymbolTable);
          org.eclipse.biscuit.datalog.Check check = c.convert(symbolTable);

          for (int k = 0; k < check.queries().size(); k++) {
            org.eclipse.biscuit.datalog.Rule query = check.queries().get(k);
            TrustedOrigins ruleTrustedOrigins =
                TrustedOrigins.fromScopes(
                    query.scopes(), blockTrustedOrigins, i + 1, this.publicKeyToBlockId);
            switch (check.kind()) {
              case ONE:
                successful =
                    world.queryMatch(query, (long) i + 1, ruleTrustedOrigins, symbolTable, budget);
                break;
              case ALL:
                successful = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable, budget);
                break;
              case REJECT:
                successful =
                    world.queryMatch(query, (long) i + 1, ruleTrustedOrigins, symbolTable, budget);
                break;
              default:
                throw new RuntimeException("unmapped kind");
            }

            if (Instant.now().compareTo(timeLimit) >= 0) {
              throw new Error.Timeout();
            }

            if (successful) {
              break;
            }
          }

          if (successful == (check.kind() == REJECT)) {
            errors.add(new FailedCheck.FailedBlock(i + 1, j, symbolTable.formatCheck(check)));
          }
        }
      }
    }

    if (policyResult.isPresent()) {
      var e = policyResult.get();
      if (e.isOk()) {
        if (errors.isEmpty()) {
          return e.getOk().longValue();
        } else {
          throw new Error.FailedLogic(
              new LogicError.Unauthorized(new LogicError.MatchedPolicy.Allow(e.getOk()), errors));
        }
      } else {
        throw new Error.FailedLogic(
            new LogicError.Unauthorized(new LogicError.MatchedPolicy.Deny(e.getErr()), errors));
      }
    } else {
      throw new Error.FailedLogic(new LogicError.NoMatchingPolicy(errors));
    }
  }

  public String formatWorld() {
    StringBuilder facts = new StringBuilder();
    for (Map.Entry<Origin, List<org.eclipse.biscuit.datalog.Fact>> entry :
        this.world.getFacts().byOrigin().entrySet()) {
      facts.append("\n\t\t").append(entry.getKey()).append(":");
      for (org.eclipse.biscuit.datalog.Fact f : entry.getValue()) {
        facts.append("\n\t\t\t");
        facts.append(this.symbolTable.formatFact(f));
      }
    }
    final List<String> rules =
        this.world.getRules().stream()
            .map(this.symbolTable::formatRule)
            .collect(Collectors.toList());

    List<String> checks = new ArrayList<>();

    for (int j = 0; j < this.checks.size(); j++) {
      checks.add("Authorizer[" + j + "]: " + this.checks.get(j));
    }

    if (this.token != null) {
      for (int j = 0; j < this.token.authority.getChecks().size(); j++) {
        checks.add(
            "Block[0]["
                + j
                + "]: "
                + token.symbolTable.formatCheck(this.token.authority.getChecks().get(j)));
      }

      for (int i = 0; i < this.token.blocks.size(); i++) {
        Block b = this.token.blocks.get(i);

        SymbolTable blockSymbolTable = token.symbolTable;
        if (b.getExternalKey().isPresent()) {
          blockSymbolTable = new SymbolTable(b.getSymbolTable(), b.getPublicKeys());
        }

        for (int j = 0; j < b.getChecks().size(); j++) {
          checks.add(
              "Block["
                  + (i + 1)
                  + "]["
                  + j
                  + "]: "
                  + blockSymbolTable.formatCheck(b.getChecks().get(j)));
        }
      }
    }

    List<String> policies = new ArrayList<>();
    for (Policy policy : this.policies) {
      policies.add(policy.toString());
    }

    return "World {\n\tfacts: ["
        + facts
        // String.join(",\n\t\t", facts) +
        + "\n\t],\n\trules: [\n\t\t"
        + String.join(",\n\t\t", rules)
        + "\n\t],\n\tchecks: [\n\t\t"
        + String.join(",\n\t\t", checks)
        + "\n\t],\n\tpolicies: [\n\t\t"
        + String.join(",\n\t\t", policies)
        + "\n\t]\n}";
  }

  public FactSet getFacts() {
    return this.world.getFacts();
  }

  public RuleSet getRules() {
    return this.world.getRules();
  }

  public List<Pair<Long, List<Check>>> getChecks() {
    List<Pair<Long, List<Check>>> allChecks = new ArrayList<>();
    if (!this.checks.isEmpty()) {
      allChecks.add(new Pair<>(Long.MAX_VALUE, this.checks));
    }

    List<Check> authorityChecks = new ArrayList<>();
    for (org.eclipse.biscuit.datalog.Check check : this.token.authority.getChecks()) {
      authorityChecks.add(Check.convertFrom(check, this.token.symbolTable));
    }
    if (!authorityChecks.isEmpty()) {
      allChecks.add(new Pair<>((long) 0, authorityChecks));
    }

    long count = 1;
    for (Block block : this.token.blocks) {
      List<Check> blockChecks = new ArrayList<>();

      if (block.getExternalKey().isPresent()) {
        SymbolTable blockSymbolTable =
            new SymbolTable(block.getSymbolTable(), block.getPublicKeys());
        for (org.eclipse.biscuit.datalog.Check check : block.getChecks()) {
          blockChecks.add(Check.convertFrom(check, blockSymbolTable));
        }
      } else {
        for (org.eclipse.biscuit.datalog.Check check : block.getChecks()) {
          blockChecks.add(Check.convertFrom(check, token.symbolTable));
        }
      }
      if (!blockChecks.isEmpty()) {
        allChecks.add(new Pair<>(count, blockChecks));
      }
      count += 1;
    }

    return allChecks;
  }

  public List<Policy> getPolicies() {
    return this.policies;
  }

  public SymbolTable getSymbolTable() {
    return symbolTable;
  }
}
