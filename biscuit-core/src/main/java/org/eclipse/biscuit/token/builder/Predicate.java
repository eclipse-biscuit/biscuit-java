/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.eclipse.biscuit.datalog.SymbolTable;

public final class Predicate implements Cloneable {
  String name;
  List<Term> terms;

  public Predicate(String name, List<Term> terms) {
    this.name = name;
    this.terms = terms;
  }

  public String getName() {
    return name;
  }

  public List<Term> getTerms() {
    return terms;
  }

  public org.eclipse.biscuit.datalog.Predicate convert(SymbolTable symbolTable) {
    long name = symbolTable.insert(this.name);
    ArrayList<org.eclipse.biscuit.datalog.Term> terms = new ArrayList<>();

    for (Term a : this.terms) {
      terms.add(a.convert(symbolTable));
    }

    return new org.eclipse.biscuit.datalog.Predicate(name, terms);
  }

  public static Predicate convertFrom(
      org.eclipse.biscuit.datalog.Predicate p, SymbolTable symbolTable) {
    String name = symbolTable.formatSymbol((int) p.name());
    List<Term> terms = new ArrayList<>();
    for (org.eclipse.biscuit.datalog.Term t : p.terms()) {
      terms.add(t.toTerm(symbolTable));
    }

    return new Predicate(name, terms);
  }

  @Override
  public String toString() {
    final List<String> i =
        terms.stream().map((term) -> term.toString()).collect(Collectors.toList());
    return "" + name + "(" + String.join(", ", i) + ")";
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Predicate predicate = (Predicate) o;

    if (name != null ? !name.equals(predicate.name) : predicate.name != null) {
      return false;
    }
    return terms != null ? terms.equals(predicate.terms) : predicate.terms == null;
  }

  @Override
  public int hashCode() {
    int result = name != null ? name.hashCode() : 0;
    result = 31 * result + (terms != null ? terms.hashCode() : 0);
    return result;
  }

  @Override
  public Predicate clone() {
    String name = this.name;
    List<Term> terms = new ArrayList<Term>(this.terms.size());
    terms.addAll(this.terms);
    return new Predicate(name, terms);
  }
}
