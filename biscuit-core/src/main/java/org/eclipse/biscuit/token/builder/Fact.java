/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.FailedCheck;

public final class Fact implements Cloneable {
  Predicate predicate;
  Optional<Map<String, Optional<Term>>> variables;

  public Fact(String name, List<Term> terms) {
    Map<String, Optional<Term>> variables = new HashMap<String, Optional<Term>>();
    for (Term term : terms) {
      if (term instanceof Term.Variable) {
        variables.put(((Term.Variable) term).value, Optional.empty());
      }
    }
    this.predicate = new Predicate(name, terms);
    this.variables = Optional.of(variables);
  }

  public Fact(Predicate p) {
    this.predicate = p;
    this.variables = Optional.empty();
  }

  private Fact(Predicate predicate, Optional<Map<String, Optional<Term>>> variables) {
    this.predicate = predicate;
    this.variables = variables;
  }

  public void validate() throws Error.Language {
    if (!this.variables.isEmpty()) {
      List<String> invalidVariables =
          variables.get().entrySet().stream()
              .flatMap(
                  e -> {
                    if (e.getValue().isEmpty()) {
                      return Stream.of(e.getKey());
                    } else {
                      return Stream.empty();
                    }
                  })
              .collect(Collectors.toList());
      if (!invalidVariables.isEmpty()) {
        throw new Error.Language(new FailedCheck.LanguageError.Builder(invalidVariables));
      }
    }
  }

  public Fact set(String name, Term term) throws Error.Language {
    if (this.variables.isEmpty()) {
      throw new Error.Language(new FailedCheck.LanguageError.UnknownVariable(name));
    }
    Map<String, Optional<Term>> localVariables = this.variables.get();
    Optional<Term> r = localVariables.get(name);
    if (r != null) {
      localVariables.put(name, Optional.of(term));
    } else {
      throw new Error.Language(new FailedCheck.LanguageError.UnknownVariable(name));
    }
    return this;
  }

  public Fact applyVariables() {
    this.variables.ifPresent(
        laVariables -> {
          this.predicate.terms =
              this.predicate.terms.stream()
                  .flatMap(
                      t -> {
                        if (t instanceof Term.Variable) {
                          Optional<Term> term =
                              laVariables.getOrDefault(((Term.Variable) t).value, Optional.empty());
                          return term.map(t2 -> Stream.of(t2)).orElse(Stream.empty());
                        } else {
                          return Stream.of(t);
                        }
                      })
                  .collect(Collectors.toList());
        });
    return this;
  }

  public org.eclipse.biscuit.datalog.Fact convert(SymbolTable symbolTable) {
    Fact f = this.clone();
    f.applyVariables();
    return new org.eclipse.biscuit.datalog.Fact(f.predicate.convert(symbolTable));
  }

  public static Fact convertFrom(org.eclipse.biscuit.datalog.Fact f, SymbolTable symbolTable) {
    return new Fact(Predicate.convertFrom(f.predicate(), symbolTable));
  }

  @Override
  public String toString() {
    Fact f = this.clone();
    f.applyVariables();
    return f.predicate.toString();
  }

  public String name() {
    return this.predicate.name;
  }

  public List<Term> terms() {
    return this.predicate.terms;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Fact fact = (Fact) o;

    return predicate != null ? predicate.equals(fact.predicate) : fact.predicate == null;
  }

  @Override
  public int hashCode() {
    return predicate != null ? predicate.hashCode() : 0;
  }

  @Override
  public Fact clone() {
    Predicate p = this.predicate.clone();
    Optional<Map<String, Optional<Term>>> variables =
        this.variables.map(
            v -> {
              Map<String, Optional<Term>> m = new HashMap<>();
              m.putAll(v);
              return m;
            });
    return new Fact(p, variables);
  }
}
