/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import static org.eclipse.biscuit.datalog.Check.Kind.ONE;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.Authorizer;
import org.eclipse.biscuit.token.Biscuit;
import org.eclipse.biscuit.token.Policy;
import org.eclipse.biscuit.token.builder.parser.Parser;

public final class AuthorizerBuilder {
  private final List<Fact> facts = new ArrayList<>();
  private final List<Rule> rules = new ArrayList<>();
  private final List<Check> checks = new ArrayList<>();
  private final List<Scope> scopes = new ArrayList<>();
  private final List<Policy> policies = new ArrayList<>();
  private RunLimits limits = new RunLimits();

  public AuthorizerBuilder() {}

  public AuthorizerBuilder clone() {
    AuthorizerBuilder clone = new AuthorizerBuilder();
    clone.facts.addAll(this.facts);
    clone.rules.addAll(this.rules);
    clone.checks.addAll(this.checks);
    clone.scopes.addAll(this.scopes);
    clone.policies.addAll(this.policies);
    clone.limits =
        new RunLimits(
            this.limits.getMaxFacts(),
            this.limits.getMaxIterations(),
            this.limits.getMaxTime(),
            this.limits.getMaxSteps());
    return clone;
  }

  public AuthorizerBuilder addFact(Fact fact) {
    this.facts.add(fact);
    return this;
  }

  public AuthorizerBuilder addFact(String s) throws Error.Parser {
    var res = Parser.fact(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return this.addFact(res.getOk()._2);
  }

  public AuthorizerBuilder addRule(Rule rule) {
    this.rules.add(rule);
    return this;
  }

  public AuthorizerBuilder addRule(String s) throws Error.Parser {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return this.addRule(res.getOk()._2);
  }

  public AuthorizerBuilder addCheck(Check check) {
    this.checks.add(check);
    return this;
  }

  public AuthorizerBuilder addCheck(String s) throws Error.Parser {
    var res = Parser.check(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return this.addCheck(res.getOk()._2);
  }

  public AuthorizerBuilder addScope(Scope scope) {
    this.scopes.add(scope);
    return this;
  }

  public AuthorizerBuilder addPolicy(Policy policy) {
    this.policies.add(policy);
    return this;
  }

  public AuthorizerBuilder addPolicy(String s) throws Error.Parser {
    var res = Parser.policy(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return this.addPolicy(res.getOk()._2);
  }

  public Result<AuthorizerBuilder, Map<Integer, List<Error>>> addDatalog(String s) {
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
    this.facts.addAll(components.facts);
    this.rules.addAll(components.rules);
    this.checks.addAll(components.checks);
    this.scopes.addAll(components.scopes);
    this.policies.addAll(components.policies);

    return Result.ok(this);
  }

  public AuthorizerBuilder setTime() throws Error.Language {
    return this.addFact(Utils.fact("time", List.of(Utils.date(new Date()))));
  }

  public AuthorizerBuilder allow() {
    return this.addPolicy(
        new Policy(
            Utils.constrainedRule(
                "allow", new ArrayList<>(), new ArrayList<>(), List.of(new Term.Bool(true))),
            Policy.Kind.ALLOW));
  }

  public AuthorizerBuilder deny() {
    return this.addPolicy(
        new Policy(
            Utils.constrainedRule(
                "deny", new ArrayList<>(), new ArrayList<>(), List.of(new Term.Bool(true))),
            Policy.Kind.DENY));
  }

  public AuthorizerBuilder addResource(String name) {
    return this.addFact(new Fact("resource", List.of(Utils.string(name))));
  }

  public AuthorizerBuilder addOperation(String name) {
    return this.addFact(new Fact("operation", List.of(Utils.string(name))));
  }

  public AuthorizerBuilder checkResource(String name) {
    return this.addCheck(
        new Check(
            ONE,
            Utils.rule(
                "resource_check",
                List.of(Utils.string("resource_check")),
                List.of(Utils.pred("resource", List.of(Utils.string(name)))))));
  }

  public AuthorizerBuilder checkOperation(String name) {
    return this.addCheck(
        new Check(
            ONE,
            Utils.rule(
                "operation_check",
                List.of(Utils.string("operation_check")),
                List.of(Utils.pred("operation", List.of(Utils.string(name)))))));
  }

  public AuthorizerBuilder resourcePrefix(String prefix) {
    return this.mergeBlock(new Block().resourcePrefix(prefix));
  }

  public AuthorizerBuilder resourceSuffix(String suffix) {
    return this.mergeBlock(new Block().resourceSuffix(suffix));
  }

  public AuthorizerBuilder setExpirationDate(Date date) {
    return this.mergeBlock(new Block().setExpirationDate(date));
  }

  public AuthorizerBuilder setLimits(RunLimits limits) {
    this.limits = limits;
    return this;
  }

  public RunLimits limits() {
    return this.limits;
  }

  public AuthorizerBuilder mergeBlock(Block block) {
    this.facts.addAll(block.facts());
    this.rules.addAll(block.rules());
    this.checks.addAll(block.checks());
    this.scopes.addAll(block.scopes());
    return this;
  }

  public AuthorizerBuilder merge(AuthorizerBuilder other) {
    this.facts.addAll(other.facts);
    this.rules.addAll(other.rules);
    this.checks.addAll(other.checks);
    this.scopes.addAll(other.scopes);
    this.policies.addAll(other.policies);
    return this;
  }

  public Authorizer build(Biscuit token) throws Error.FailedLogic {
    return Authorizer.make(this, token);
  }

  public Authorizer buildUnauthenticated() throws Error.FailedLogic {
    return Authorizer.make(this, null);
  }

  public List<Fact> facts() {
    return this.facts;
  }

  public List<Rule> rules() {
    return this.rules;
  }

  public List<Check> checks() {
    return this.checks;
  }

  public List<Scope> scopes() {
    return this.scopes;
  }

  public List<Policy> policies() {
    return this.policies;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    for (Fact fact : this.facts) {
      s.append(fact).append(";\n");
    }
    if (!this.facts.isEmpty()) {
      s.append("\n");
    }
    for (Rule rule : this.rules) {
      s.append(rule).append(";\n");
    }
    if (!this.rules.isEmpty()) {
      s.append("\n");
    }
    for (Check check : this.checks) {
      s.append(check).append(";\n");
    }
    if (!this.checks.isEmpty()) {
      s.append("\n");
    }
    for (Policy policy : this.policies) {
      s.append(policy).append(";\n");
    }
    return s.toString();
  }
}
