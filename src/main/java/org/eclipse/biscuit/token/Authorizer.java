/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
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
import org.eclipse.biscuit.datalog.FactSet;
import org.eclipse.biscuit.datalog.Origin;
import org.eclipse.biscuit.datalog.Pair;
import org.eclipse.biscuit.datalog.RuleSet;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.datalog.Scope;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.TrustedOrigins;
import org.eclipse.biscuit.datalog.World;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.FailedCheck;
import org.eclipse.biscuit.error.LogicError;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.builder.Check;
import org.eclipse.biscuit.token.builder.Expression;
import org.eclipse.biscuit.token.builder.Fact;
import org.eclipse.biscuit.token.builder.Rule;
import org.eclipse.biscuit.token.builder.Term;
import org.eclipse.biscuit.token.builder.Utils;
import org.eclipse.biscuit.token.builder.parser.Parser;

/** Token verification class */
public final class Authorizer {
  private Biscuit token;
  private final List<Check> checks;
  private final List<Policy> policies;
  private final List<Scope> scopes;
  private final HashMap<Long, List<Long>> publicKeyToBlockId;
  private final World world;
  private final SymbolTable symbolTable;

  private Authorizer(Biscuit token, World w) throws Error.FailedLogic {
    this.token = token;
    this.world = w;
    this.symbolTable = new SymbolTable(this.token.symbolTable);
    this.checks = new ArrayList<>();
    this.policies = new ArrayList<>();
    this.scopes = new ArrayList<>();
    this.publicKeyToBlockId = new HashMap<>();
    updateOnToken();
  }

  /**
   * Creates an empty authorizer
   *
   * <p>used to apply policies when unauthenticated (no token) and to preload an authorizer that is
   * cloned for each new request
   */
  public Authorizer() {
    this.world = new World();
    this.symbolTable = Biscuit.defaultSymbolTable();
    this.checks = new ArrayList<>();
    this.policies = new ArrayList<>();
    this.scopes = new ArrayList<>();
    this.publicKeyToBlockId = new HashMap<>();
  }

  private Authorizer(
      Biscuit token,
      List<Check> checks,
      List<Policy> policies,
      World world,
      SymbolTable symbolTable) {
    this.token = token;
    this.checks = checks;
    this.policies = policies;
    this.world = world;
    this.symbolTable = symbolTable;
    this.scopes = new ArrayList<>();
    this.publicKeyToBlockId = new HashMap<>();
  }

  /**
   * Creates a authorizer for a token
   *
   * <p>also checks that the token is valid for this root public key
   *
   * @param token
   * @return Authorizer
   */
  public static Authorizer make(Biscuit token) throws Error.FailedLogic {
    return new Authorizer(token, new World());
  }

  public Authorizer clone() {
    return new Authorizer(
        this.token,
        new ArrayList<>(this.checks),
        new ArrayList<>(this.policies),
        new World(this.world),
        new SymbolTable(this.symbolTable));
  }

  public void updateOnToken() throws Error.FailedLogic {
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
        TrustedOrigins blockTrustedOrigins =
            TrustedOrigins.fromScopes(
                block.getScopes(), TrustedOrigins.defaultOrigins(), i + 1, this.publicKeyToBlockId);

        SymbolTable blockSymbolTable = token.symbolTable;

        if (block.getExternalKey().isPresent()) {
          blockSymbolTable = new SymbolTable(block.getSymbolTable(), block.getPublicKeys());
        }

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
          world.addRule((long) i + 1, ruleTrustedOrigins, convertedRule);
        }
      }
    }
  }

  public Authorizer addToken(Biscuit token) throws Error.FailedLogic {
    if (this.token != null) {
      throw new Error.FailedLogic(new LogicError.AuthorizerNotEmpty());
    }

    this.token = token;
    updateOnToken();
    return this;
  }

  public Result<Authorizer, Map<Integer, List<Error>>> addDatalog(String s) {
    var result = Parser.datalogComponents(s);

    if (result.isErr()) {
      var errors = result.getErr();
      Map<Integer, List<Error>> errorMap = new HashMap<>();
      for (Map.Entry<Integer, List<org.eclipse.biscuit.token.builder.parser.Error>> entry :
          errors.entrySet()) {
        List<Error> errorsList = new ArrayList<>();
        for (org.eclipse.biscuit.token.builder.parser.Error error : entry.getValue()) {
          errorsList.add(new Error.Parser(error));
        }
        errorMap.put(entry.getKey(), errorsList);
      }
      return Result.err(errorMap);
    }

    var components = result.getOk();
    components.facts.forEach(this::addFact);
    components.rules.forEach(this::addRule);
    components.checks.forEach(this::addCheck);
    components.scopes.forEach(this::addScope);
    components.policies.forEach(this::addPolicy);

    return Result.ok(this);
  }

  public Authorizer addScope(org.eclipse.biscuit.token.builder.Scope s) {
    this.scopes.add(s.convert(symbolTable));
    return this;
  }

  public Authorizer addFact(Fact fact) {
    world.addFact(Origin.authorizer(), fact.convert(symbolTable));
    return this;
  }

  public Authorizer addFact(String s) throws Error.Parser {
    var res = Parser.fact(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return this.addFact(res.getOk()._2);
  }

  public Authorizer addRule(Rule rule) {
    org.eclipse.biscuit.datalog.Rule r = rule.convert(symbolTable);
    TrustedOrigins ruleTrustedOrigins =
        TrustedOrigins.fromScopes(
            r.scopes(), this.authorizerTrustedOrigins(), Long.MAX_VALUE, this.publicKeyToBlockId);
    world.addRule(Long.MAX_VALUE, ruleTrustedOrigins, r);
    return this;
  }

  public Authorizer addRule(String s) throws Error.Parser {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addRule(res.getOk()._2);
  }

  public TrustedOrigins authorizerTrustedOrigins() {
    return TrustedOrigins.fromScopes(
        this.scopes, TrustedOrigins.defaultOrigins(), Long.MAX_VALUE, this.publicKeyToBlockId);
  }

  public Authorizer addCheck(Check check) {
    this.checks.add(check);
    return this;
  }

  public Authorizer addCheck(String s) throws Error.Parser {
    var res = Parser.check(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addCheck(res.getOk()._2);
  }

  public Authorizer setTime() throws Error.Language {
    world.addFact(
        Origin.authorizer(),
        Utils.fact("time", List.of(Utils.date(new Date()))).convert(symbolTable));
    return this;
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

  public Authorizer allow() {
    ArrayList<Rule> q = new ArrayList<>();

    q.add(
        Utils.constrainedRule(
            "allow",
            new ArrayList<>(),
            new ArrayList<>(),
            List.of(new Expression.Value(new Term.Bool(true)))));

    this.policies.add(new Policy(q, Policy.Kind.ALLOW));
    return this;
  }

  public Authorizer deny() {
    ArrayList<Rule> q = new ArrayList<>();

    q.add(
        Utils.constrainedRule(
            "deny",
            new ArrayList<>(),
            new ArrayList<>(),
            List.of(new Expression.Value(new Term.Bool(true)))));

    this.policies.add(new Policy(q, Policy.Kind.DENY));
    return this;
  }

  public Authorizer addPolicy(String s) throws Error.Parser {
    var res = Parser.policy(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    this.policies.add(res.getOk()._2);
    return this;
  }

  public Authorizer addPolicy(Policy p) {
    this.policies.add(p);
    return this;
  }

  public Authorizer addScope(Scope s) {
    this.scopes.add(s);
    return this;
  }

  public Set<Fact> query(Rule query) throws Error {
    return this.query(query, new RunLimits());
  }

  public Set<org.eclipse.biscuit.token.builder.Fact> query(String s) throws Error {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return query(res.getOk()._2);
  }

  public Set<Fact> query(Rule query, RunLimits limits) throws Error {
    world.run(limits, symbolTable);

    org.eclipse.biscuit.datalog.Rule rule = query.convert(symbolTable);
    TrustedOrigins ruleTrustedorigins =
        TrustedOrigins.fromScopes(
            rule.scopes(),
            TrustedOrigins.defaultOrigins(),
            Long.MAX_VALUE,
            this.publicKeyToBlockId);

    FactSet facts = world.queryRule(rule, Long.MAX_VALUE, ruleTrustedorigins, symbolTable);
    Set<Fact> s = new HashSet<>();

    for (Iterator<org.eclipse.biscuit.datalog.Fact> it = facts.stream().iterator();
        it.hasNext(); ) {
      org.eclipse.biscuit.datalog.Fact f = it.next();
      s.add(Fact.convertFrom(f, symbolTable));
    }

    return s;
  }

  public Set<org.eclipse.biscuit.token.builder.Fact> query(String s, RunLimits limits)
      throws Error {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return query(res.getOk()._2, limits);
  }

  public Long authorize() throws Error {
    return this.authorize(new RunLimits());
  }

  public Long authorize(RunLimits limits) throws Error {
    Instant timeLimit = Instant.now().plus(limits.getMaxTime());
    List<FailedCheck> errors = new LinkedList<>();

    TrustedOrigins authorizerTrustedOrigins = this.authorizerTrustedOrigins();

    world.run(limits, symbolTable);

    for (int i = 0; i < this.checks.size(); i++) {
      org.eclipse.biscuit.datalog.Check c = this.checks.get(i).convert(symbolTable);
      boolean successful = false;

      for (int j = 0; j < c.queries().size(); j++) {
        boolean res = false;
        org.eclipse.biscuit.datalog.Rule query = c.queries().get(j);
        TrustedOrigins ruleTrustedOrigins =
            TrustedOrigins.fromScopes(
                query.scopes(), authorizerTrustedOrigins, Long.MAX_VALUE, this.publicKeyToBlockId);
        switch (c.kind()) {
          case ONE:
            res = world.queryMatch(query, Long.MAX_VALUE, ruleTrustedOrigins, symbolTable);
            break;
          case ALL:
            res = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable);
            break;
          default:
            throw new RuntimeException("unmapped kind");
        }

        if (Instant.now().compareTo(timeLimit) >= 0) {
          throw new Error.Timeout();
        }

        if (res) {
          successful = true;
          break;
        }
      }

      if (!successful) {
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
          boolean res = false;
          org.eclipse.biscuit.datalog.Rule query = check.queries().get(k);
          TrustedOrigins ruleTrustedOrigins =
              TrustedOrigins.fromScopes(
                  query.scopes(), authorityTrustedOrigins, 0, this.publicKeyToBlockId);
          switch (check.kind()) {
            case ONE:
              res = world.queryMatch(query, (long) 0, ruleTrustedOrigins, symbolTable);
              break;
            case ALL:
              res = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable);
              break;
            default:
              throw new RuntimeException("unmapped kind");
          }

          if (Instant.now().compareTo(timeLimit) >= 0) {
            throw new Error.Timeout();
          }

          if (res) {
            successful = true;
            break;
          }
        }

        if (!successful) {
          errors.add(new FailedCheck.FailedBlock(0, j, symbolTable.formatCheck(check)));
        }
      }
    }

    Optional<Result<Integer, Integer>> policyResult = Optional.empty();
    policies_test:
    for (int i = 0; i < this.policies.size(); i++) {
      Policy policy = this.policies.get(i);

      for (int j = 0; j < policy.queries().size(); j++) {
        org.eclipse.biscuit.datalog.Rule query = policy.queries().get(j).convert(symbolTable);
        TrustedOrigins policyTrustedOrigins =
            TrustedOrigins.fromScopes(
                query.scopes(), authorizerTrustedOrigins, Long.MAX_VALUE, this.publicKeyToBlockId);
        boolean res = world.queryMatch(query, Long.MAX_VALUE, policyTrustedOrigins, symbolTable);

        if (Instant.now().compareTo(timeLimit) >= 0) {
          throw new Error.Timeout();
        }

        if (res) {
          if (this.policies.get(i).kind() == Policy.Kind.ALLOW) {
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
        TrustedOrigins blockTrustedOrigins =
            TrustedOrigins.fromScopes(
                b.getScopes(), TrustedOrigins.defaultOrigins(), i + 1, this.publicKeyToBlockId);
        SymbolTable blockSymbolTable = token.symbolTable;
        if (b.getExternalKey().isPresent()) {
          blockSymbolTable = new SymbolTable(b.getSymbolTable(), b.getPublicKeys());
        }

        for (int j = 0; j < b.getChecks().size(); j++) {
          boolean successful = false;

          Check c = Check.convertFrom(b.getChecks().get(j), blockSymbolTable);
          org.eclipse.biscuit.datalog.Check check = c.convert(symbolTable);

          for (int k = 0; k < check.queries().size(); k++) {
            boolean res = false;
            org.eclipse.biscuit.datalog.Rule query = check.queries().get(k);
            TrustedOrigins ruleTrustedOrigins =
                TrustedOrigins.fromScopes(
                    query.scopes(), blockTrustedOrigins, i + 1, this.publicKeyToBlockId);
            switch (check.kind()) {
              case ONE:
                res = world.queryMatch(query, (long) i + 1, ruleTrustedOrigins, symbolTable);
                break;
              case ALL:
                res = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable);
                break;
              default:
                throw new RuntimeException("unmapped kind");
            }

            if (Instant.now().compareTo(timeLimit) >= 0) {
              throw new Error.Timeout();
            }

            if (res) {
              successful = true;
              break;
            }
          }

          if (!successful) {
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
    for (Map.Entry<Origin, HashSet<org.eclipse.biscuit.datalog.Fact>> entry :
        this.world.getFacts().facts().entrySet()) {
      facts.append("\n\t\t" + entry.getKey() + ":");
      for (org.eclipse.biscuit.datalog.Fact f : entry.getValue()) {
        facts.append("\n\t\t\t");
        facts.append(this.symbolTable.formatFact(f));
      }
    }
    final List<String> rules =
        this.world.getRules().stream()
            .map((r) -> this.symbolTable.formatRule(r))
            .collect(Collectors.toList());

    List<String> checks = new ArrayList<>();

    for (int j = 0; j < this.checks.size(); j++) {
      checks.add("Authorizer[" + j + "]: " + this.checks.get(j).toString());
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
        + facts.toString()
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
