/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.eclipse.biscuit.datalog.Check.Kind;
import org.eclipse.biscuit.datalog.SymbolTable;

public final class Check {
  private final Kind kind;
  private final List<Rule> queries;

  public Check(Kind kind, List<Rule> queries) {
    this.kind = kind;
    this.queries = queries;
  }

  public Check(Kind kind, Rule query) {
    this.kind = kind;

    // Checks are queries that match facts, not rules that generate facts.
    // Replace the rule's head with a placeholder predicate since checks only use the body,
    // expressions, and scopes.
    Rule q =
        new Rule(
            new Predicate("query", new ArrayList<>()), query.body, query.expressions, query.scopes);
    ArrayList<Rule> r = new ArrayList<>();
    r.add(q);
    queries = r;
  }

  public org.eclipse.biscuit.datalog.Check convert(SymbolTable symbolTable) {
    ArrayList<org.eclipse.biscuit.datalog.Rule> queries = new ArrayList<>();

    for (Rule q : this.queries) {
      queries.add(q.convert(symbolTable));
    }
    return new org.eclipse.biscuit.datalog.Check(this.kind, queries);
  }

  public static Check convertFrom(org.eclipse.biscuit.datalog.Check r, SymbolTable symbolTable) {
    ArrayList<Rule> queries = new ArrayList<>();

    for (org.eclipse.biscuit.datalog.Rule q : r.queries()) {
      queries.add(Rule.convertFrom(q, symbolTable));
    }

    return new Check(r.kind(), queries);
  }

  public Kind kind() {
    return kind;
  }

  @Override
  public String toString() {
    final List<String> qs =
        queries.stream().map((q) -> q.bodyToString()).collect(Collectors.toList());

    switch (kind) {
      case ONE:
        return "check if " + String.join(" or ", qs);
      case ALL:
        return "check all " + String.join(" or ", qs);
      case REJECT:
        return "reject if " + String.join(" or ", qs);
      default:
        return "check if " + String.join(" or ", qs);
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Check check = (Check) o;

    return queries != null ? queries.equals(check.queries) : check.queries == null;
  }

  @Override
  public int hashCode() {
    return queries != null ? queries.hashCode() : 0;
  }
}
