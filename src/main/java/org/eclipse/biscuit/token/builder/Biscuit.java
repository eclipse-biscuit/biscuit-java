/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import static org.eclipse.biscuit.token.UnverifiedBiscuit.defaultSymbolTable;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.crypto.Signer;
import org.eclipse.biscuit.datalog.SchemaVersion;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.Block;
import org.eclipse.biscuit.token.builder.parser.Parser;

public final class Biscuit {
  private SecureRandom rng;
  private Signer root;
  private String context;
  private List<Fact> facts;
  private List<Rule> rules;
  private List<Check> checks;
  private List<Scope> scopes;
  private Optional<Integer> rootKeyId;

  public Biscuit(final SecureRandom rng, final Signer root) {
    this.rng = rng;
    this.root = root;
    this.context = "";
    this.facts = new ArrayList<>();
    this.rules = new ArrayList<>();
    this.checks = new ArrayList<>();
    this.scopes = new ArrayList<>();
    this.rootKeyId = Optional.empty();
  }

  public Biscuit(
      final SecureRandom rng,
      final org.eclipse.biscuit.crypto.Signer root,
      Optional<Integer> rootKeyId) {
    this.rng = rng;
    this.root = root;
    this.context = "";
    this.facts = new ArrayList<>();
    this.rules = new ArrayList<>();
    this.checks = new ArrayList<>();
    this.scopes = new ArrayList<>();
    this.rootKeyId = rootKeyId;
  }

  public Biscuit(
      final SecureRandom rng,
      final org.eclipse.biscuit.crypto.Signer root,
      Optional<Integer> rootKeyId,
      org.eclipse.biscuit.token.builder.Block block) {
    this.rng = rng;
    this.root = root;
    this.rootKeyId = rootKeyId;
    this.context = block.context();
    this.facts = block.facts();
    this.rules = block.rules();
    this.checks = block.checks();
    this.scopes = block.scopes();
  }

  public Biscuit addAuthorityFact(Fact f) throws Error.Language {
    f.validate();
    this.facts.add(f);
    return this;
  }

  public Biscuit addAuthorityFact(String s) throws Error.Parser, Error.Language {
    var res = Parser.fact(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addAuthorityFact(res.getOk()._2);
  }

  public Biscuit addAuthorityRule(Rule rule) {
    this.rules.add(rule);
    return this;
  }

  public Biscuit addAuthorityRule(String s) throws Error.Parser {
    var res = Parser.rule(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addAuthorityRule(res.getOk()._2);
  }

  public Biscuit addAuthorityCheck(Check c) {
    this.checks.add(c);
    return this;
  }

  public Biscuit addAuthorityCheck(String s) throws Error.Parser {
    var res = Parser.check(s);
    if (res.isErr()) {
      throw new Error.Parser(res.getErr());
    }
    return addAuthorityCheck(res.getOk()._2);
  }

  public Biscuit setContext(String context) {
    this.context = context;
    return this;
  }

  public Biscuit addScope(Scope scope) {
    this.scopes.add(scope);
    return this;
  }

  public void setRootKeyId(Integer i) {
    this.rootKeyId = Optional.of(i);
  }

  public org.eclipse.biscuit.token.Biscuit build() throws Error {
    return build(defaultSymbolTable());
  }

  private org.eclipse.biscuit.token.Biscuit build(SymbolTable symbolTable) throws Error {
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
    var version = new SchemaVersion(facts, rules, checks, scopes, Optional.empty()).version();

    SymbolTable blockSymbols = new SymbolTable();

    for (int i = symbolStart; i < symbolTable.symbols().size(); i++) {
      blockSymbols.add(symbolTable.symbols().get(i));
    }

    List<PublicKey> publicKeys = new ArrayList<>();
    for (int i = publicKeyStart; i < symbolTable.currentPublicKeyOffset(); i++) {
      publicKeys.add(symbolTable.getPublicKeys().get(i));
    }

    Block authorityBlock =
        new Block(
            blockSymbols,
            context,
            facts,
            rules,
            checks,
            scopes,
            publicKeys,
            Optional.empty(),
            version);

    if (this.rootKeyId.isPresent()) {
      return org.eclipse.biscuit.token.Biscuit.make(
          this.rng, this.root, this.rootKeyId.get(), authorityBlock);
    } else {
      return org.eclipse.biscuit.token.Biscuit.make(this.rng, this.root, authorityBlock);
    }
  }

  public Biscuit addRight(String resource, String right) throws Error.Language {
    return this.addAuthorityFact(
        Utils.fact("right", Arrays.asList(Utils.string(resource), Utils.str(right))));
  }
}
