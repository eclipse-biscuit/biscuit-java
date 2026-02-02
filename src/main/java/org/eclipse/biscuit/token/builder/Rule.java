/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.FailedCheck;
import org.eclipse.biscuit.error.Result;

public final class Rule implements Cloneable {
  Predicate head;
  List<Predicate> body;
  List<Expression> expressions;
  Optional<Map<String, Optional<Term>>> variables;
  List<Scope> scopes;

  public Rule(
      Predicate head, List<Predicate> body, List<Expression> expressions, List<Scope> scopes) {
    this.head = head;
    this.body = body;
    this.expressions = expressions;
    this.scopes = scopes;
    Map<String, Optional<Term>> variables = new HashMap<>();
    for (Term t : head.terms) {
      if (t instanceof Term.Variable) {
        variables.put(((Term.Variable) t).value, Optional.empty());
      }
    }
    for (Predicate p : body) {
      for (Term t : p.terms) {
        if (t instanceof Term.Variable) {
          variables.put(((Term.Variable) t).value, Optional.empty());
        }
      }
    }
    for (Expression e : expressions) {
      if (e instanceof Term) {
        Term term = (Term) e;
        if (term instanceof Term.Variable) {
          variables.put(((Term.Variable) term).value, Optional.empty());
        }
      }
    }
    this.variables = Optional.of(variables);
  }

  @Override
  public Rule clone() {
    List<Predicate> body = new ArrayList<>();
    body.addAll(this.body);
    List<Expression> expressions = new ArrayList<>();
    expressions.addAll(this.expressions);
    List<Scope> scopes = new ArrayList<>();
    scopes.addAll(this.scopes);
    Predicate head = this.head.clone();
    return new Rule(head, body, expressions, scopes);
  }

  public void set(String name, Term term) throws Error.Language {
    if (this.variables.isPresent()) {
      Optional<Optional<Term>> t = Optional.of(this.variables.get().get(name));
      if (t.get().isPresent()) {
        this.variables.get().put(name, Optional.of(term));
      } else {
        throw new Error.Language(new FailedCheck.LanguageError.UnknownVariable("name"));
      }
    } else {
      throw new Error.Language(new FailedCheck.LanguageError.UnknownVariable("name"));
    }
  }

  public void applyVariables() {
    this.variables.ifPresent(
        laVariables -> {
          this.head.terms =
              this.head.terms.stream()
                  .flatMap(
                      t -> {
                        if (t instanceof Term.Variable) {
                          Optional<Term> term =
                              laVariables.getOrDefault(((Term.Variable) t).value, Optional.empty());
                          return term.map(t2 -> Stream.of(t2)).orElse(Stream.of(t));
                        } else {
                          return Stream.of(t);
                        }
                      })
                  .collect(Collectors.toList());
          for (Predicate p : this.body) {
            p.terms =
                p.terms.stream()
                    .flatMap(
                        t -> {
                          if (t instanceof Term.Variable) {
                            Optional<Term> term =
                                laVariables.getOrDefault(
                                    ((Term.Variable) t).value, Optional.empty());
                            return term.map(t2 -> Stream.of(t2)).orElse(Stream.of(t));
                          } else {
                            return Stream.of(t);
                          }
                        })
                    .collect(Collectors.toList());
          }
          this.expressions =
              this.expressions.stream()
                  .flatMap(
                      e -> {
                        if (e instanceof Term) {
                          Term term = (Term) e;
                          if (term instanceof Term.Variable) {
                            Optional<Term> t =
                                laVariables.getOrDefault(
                                    ((Term.Variable) term).value, Optional.empty());
                            if (t.isPresent()) {
                              return Stream.of(t.get());
                            }
                          }
                        }
                        return Stream.of(e);
                      })
                  .collect(Collectors.toList());
        });
  }

  public Result<Rule, String> validateVariables() {
    Set<String> freeVariables =
        this.head.terms.stream()
            .flatMap(
                t -> {
                  if (t instanceof Term.Variable) {
                    return Stream.of(((Term.Variable) t).value);
                  } else {
                    return Stream.empty();
                  }
                })
            .collect(Collectors.toSet());

    for (Expression e : this.expressions) {
      try {
        e.gatherVariables(freeVariables);
      } catch (Error.Shadowing err) {
        return Result.err("rule expression contains closure parameters which shadow variables");
      }
    }
    if (freeVariables.isEmpty()) {
      return Result.ok(this);
    }

    for (Predicate p : this.body) {
      for (Term term : p.terms) {
        if (term instanceof Term.Variable) {
          freeVariables.remove(((Term.Variable) term).value);
          if (freeVariables.isEmpty()) {
            return Result.ok(this);
          }
        }
      }
    }

    return Result.err(
        "rule head or expressions contains variables that are not "
            + "used in predicates of the rule's body: "
            + freeVariables.toString());
  }

  public org.eclipse.biscuit.datalog.Rule convert(SymbolTable symbolTable) {
    Rule r = this.clone();
    r.applyVariables();
    ArrayList<org.eclipse.biscuit.datalog.Predicate> body = new ArrayList<>();
    ArrayList<org.eclipse.biscuit.datalog.expressions.Expression> expressions = new ArrayList<>();
    ArrayList<org.eclipse.biscuit.datalog.Scope> scopes = new ArrayList<>();

    for (Predicate p : r.body) {
      body.add(p.convert(symbolTable));
    }

    for (Expression e : r.expressions) {
      expressions.add(e.convertExpr(symbolTable));
    }

    for (Scope s : r.scopes) {
      scopes.add(s.convert(symbolTable));
    }
    org.eclipse.biscuit.datalog.Predicate head = r.head.convert(symbolTable);
    return new org.eclipse.biscuit.datalog.Rule(head, body, expressions, scopes);
  }

  public static Rule convertFrom(org.eclipse.biscuit.datalog.Rule r, SymbolTable symbolTable) {
    ArrayList<Predicate> body = new ArrayList<>();
    ArrayList<Expression> expressions = new ArrayList<>();
    ArrayList<Scope> scopes = new ArrayList<>();

    for (org.eclipse.biscuit.datalog.Predicate p : r.body()) {
      body.add(Predicate.convertFrom(p, symbolTable));
    }

    for (org.eclipse.biscuit.datalog.expressions.Expression e : r.expressions()) {
      expressions.add(Expression.convertFrom(e.getOps(), symbolTable));
    }

    for (org.eclipse.biscuit.datalog.Scope s : r.scopes()) {
      scopes.add(Scope.convertFrom(s, symbolTable));
    }

    Predicate head = Predicate.convertFrom(r.head(), symbolTable);
    return new Rule(head, body, expressions, scopes);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Rule rule = (Rule) o;

    if (head != null ? !head.equals(rule.head) : rule.head != null) {
      return false;
    }
    if (body != null ? !body.equals(rule.body) : rule.body != null) {
      return false;
    }
    if (scopes != null ? !scopes.equals(rule.scopes) : rule.scopes != null) {
      return false;
    }
    return expressions != null ? expressions.equals(rule.expressions) : rule.expressions == null;
  }

  @Override
  public int hashCode() {
    int result = head != null ? head.hashCode() : 0;
    result = 31 * result + (body != null ? body.hashCode() : 0);
    result = 31 * result + (expressions != null ? expressions.hashCode() : 0);
    result = 31 * result + (scopes != null ? scopes.hashCode() : 0);
    return result;
  }

  public String bodyToString() {
    Rule r = this.clone();
    r.applyVariables();
    String res = "";

    if (!r.body.isEmpty()) {
      final List<String> b =
          r.body.stream().map((pred) -> pred.toString()).collect(Collectors.toList());
      res += String.join(", ", b);
    }

    if (!r.expressions.isEmpty()) {
      if (!r.body.isEmpty()) {
        res += ", ";
      }
      final List<String> e =
          r.expressions.stream()
              .map((expression) -> expression.toString())
              .collect(Collectors.toList());
      res += String.join(", ", e);
    }

    if (!r.scopes.isEmpty()) {
      if (!r.body.isEmpty() || !r.expressions.isEmpty()) {
        res += " ";
      }
      final List<String> e =
          r.scopes.stream().map((scope) -> scope.toString()).collect(Collectors.toList());
      res += "trusting " + String.join(", ", e);
    }

    return res;
  }

  @Override
  public String toString() {
    Rule r = this.clone();
    r.applyVariables();
    return r.head.toString() + " <- " + bodyToString();
  }
}
