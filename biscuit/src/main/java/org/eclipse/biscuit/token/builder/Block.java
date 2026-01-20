/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import static org.eclipse.biscuit.datalog.Check.Kind.ONE;
import static org.eclipse.biscuit.token.UnverifiedBiscuit.defaultSymbolTable;
import static org.eclipse.biscuit.token.builder.Utils.constrainedRule;
import static org.eclipse.biscuit.token.builder.Utils.date;
import static org.eclipse.biscuit.token.builder.Utils.pred;
import static org.eclipse.biscuit.token.builder.Utils.rule;
import static org.eclipse.biscuit.token.builder.Utils.str;
import static org.eclipse.biscuit.token.builder.Utils.string;
import static org.eclipse.biscuit.token.builder.Utils.var;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.SchemaVersion;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.LogicError;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.builder.parser.Parser;

public final class Block {
  private String context;
  private List<Fact> facts;
  private List<Rule> rules;
  private List<Check> checks;
  private List<Scope> scopes;

  public Block() {
    this.context = "";
    this.facts = new ArrayList<>();
    this.rules = new ArrayList<>();
    this.checks = new ArrayList<>();
    this.scopes = new ArrayList<>();
  }

  public Block addFact(Fact f) {
    this.facts.add(f);
    return this;
  }

  public Block addFact(String s) throws Error.Parser {
    var res = Parser.fact(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addFact(res.getOk()._2);
  }

  public Result<Block, Error.FailedLogic> addRule(Rule rule, boolean validate) {
    if (validate) {
      var valid = rule.validateVariables();
      if (valid.isErr()) {
        return Result.err(
            new Error.FailedLogic(new LogicError.InvalidBlockRule(0, valid.getErr())));
      }
    }
    this.rules.add(rule);
    return Result.ok(this);
  }

  public Block addRule(Rule rule) {
    this.rules.add(rule);
    return this;
  }

  public Block addRule(String s) throws Error.Parser {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addRule(res.getOk()._2);
  }

  public Block addCheck(Check check) {
    this.checks.add(check);
    return this;
  }

  public Block addCheck(String s) throws Error.Parser {
    var res = Parser.check(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addCheck(res.getOk()._2);
  }

  public Block addScope(Scope scope) {
    this.scopes.add(scope);
    return this;
  }

  public Block setContext(String context) {
    this.context = context;
    return this;
  }

  public org.eclipse.biscuit.token.Block build() {
    return build(defaultSymbolTable(), Optional.empty());
  }

  public org.eclipse.biscuit.token.Block build(final Optional<PublicKey> externalKey) {
    return build(defaultSymbolTable(), externalKey);
  }

  public org.eclipse.biscuit.token.Block build(SymbolTable symbolTable) {
    return build(symbolTable, Optional.empty());
  }

  public org.eclipse.biscuit.token.Block build(
      SymbolTable symbolTable, final Optional<PublicKey> externalKey) {
    if (externalKey.isPresent()) {
      symbolTable = new SymbolTable();
    }
    final int symbolStart = symbolTable.currentOffset();
    final int publicKeyStart = symbolTable.currentPublicKeyOffset();

    List<org.eclipse.biscuit.datalog.Fact> facts = new ArrayList<>();
    for (Fact f : this.facts) {
      facts.add(f.convert(symbolTable));
    }
    List<org.eclipse.biscuit.datalog.Rule> rules = new ArrayList<>();
    for (Rule r : this.rules) {
      rules.add(r.convert(symbolTable));
    }
    List<org.eclipse.biscuit.datalog.Check> checks = new ArrayList<>();
    for (Check c : this.checks) {
      checks.add(c.convert(symbolTable));
    }
    List<org.eclipse.biscuit.datalog.Scope> scopes = new ArrayList<>();
    for (Scope s : this.scopes) {
      scopes.add(s.convert(symbolTable));
    }
    var version = new SchemaVersion(facts, rules, checks, scopes, externalKey).version();

    SymbolTable blockSymbols = new SymbolTable();

    for (int i = symbolStart; i < symbolTable.symbols().size(); i++) {
      blockSymbols.add(symbolTable.symbols().get(i));
    }

    List<PublicKey> publicKeys = new ArrayList<>();
    for (int i = publicKeyStart; i < symbolTable.currentPublicKeyOffset(); i++) {
      publicKeys.add(symbolTable.getPublicKeys().get(i));
    }

    return new org.eclipse.biscuit.token.Block(
        blockSymbols, this.context, facts, rules, checks, scopes, publicKeys, externalKey, version);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Block block = (Block) o;

    if (!Objects.equals(context, block.context)) {
      return false;
    }
    if (!Objects.equals(facts, block.facts)) {
      return false;
    }
    if (!Objects.equals(rules, block.rules)) {
      return false;
    }
    if (!Objects.equals(checks, block.checks)) {
      return false;
    }
    return Objects.equals(scopes, block.scopes);
  }

  @Override
  public int hashCode() {
    int result = context != null ? context.hashCode() : 0;
    result = 31 * result + (facts != null ? facts.hashCode() : 0);
    result = 31 * result + (rules != null ? rules.hashCode() : 0);
    result = 31 * result + (checks != null ? checks.hashCode() : 0);
    result = 31 * result + (scopes != null ? scopes.hashCode() : 0);
    return result;
  }

  public Block checkRight(String right) {
    ArrayList<Rule> queries = new ArrayList<>();
    queries.add(
        rule(
            "check_right",
            Arrays.asList(str(right)),
            Arrays.asList(
                pred("resource", Arrays.asList(var("resource"))),
                pred("operation", Arrays.asList(str(right))),
                pred("right", Arrays.asList(var("resource"), str(right))))));
    return this.addCheck(new Check(ONE, queries));
  }

  public Block resourcePrefix(String prefix) {
    ArrayList<Rule> queries = new ArrayList<>();

    queries.add(
        constrainedRule(
            "prefix",
            Arrays.asList(var("resource")),
            Arrays.asList(pred("resource", Arrays.asList(var("resource")))),
            Arrays.asList(
                new Expression.Binary(Expression.OpCode.Prefix, var("resource"), string(prefix)))));
    return this.addCheck(new Check(ONE, queries));
  }

  public Block resourceSuffix(String suffix) {
    ArrayList<Rule> queries = new ArrayList<>();

    queries.add(
        constrainedRule(
            "suffix",
            Arrays.asList(var("resource")),
            Arrays.asList(pred("resource", Arrays.asList(var("resource")))),
            Arrays.asList(
                new Expression.Binary(Expression.OpCode.Suffix, var("resource"), string(suffix)))));
    return this.addCheck(new Check(ONE, queries));
  }

  public Block setExpirationDate(Date d) {
    ArrayList<Rule> queries = new ArrayList<>();

    queries.add(
        constrainedRule(
            "expiration",
            Arrays.asList(var("date")),
            Arrays.asList(pred("time", Arrays.asList(var("date")))),
            Arrays.asList(
                new Expression.Binary(Expression.OpCode.LessOrEqual, var("date"), date(d)))));
    return this.addCheck(new Check(ONE, queries));
  }

  public String context() {
    return context;
  }

  public List<Fact> facts() {
    return Collections.unmodifiableList(facts);
  }

  public List<Rule> rules() {
    return Collections.unmodifiableList(rules);
  }

  public List<Check> checks() {
    return Collections.unmodifiableList(checks);
  }

  public List<Scope> scopes() {
    return scopes;
  }
}
