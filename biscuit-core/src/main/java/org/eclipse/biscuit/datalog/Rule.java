/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.eclipse.biscuit.datalog.expressions.Expression;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.DeserializationLimit;

public final class Rule {
  private final Predicate head;
  private final List<Predicate> body;
  private final List<Expression> expressions;
  private final List<Scope> scopes;

  public Predicate head() {
    return this.head;
  }

  public List<Predicate> body() {
    return this.body;
  }

  public List<Expression> expressions() {
    return this.expressions;
  }

  public List<Scope> scopes() {
    return scopes;
  }

  public Stream<Result<Pair<Origin, Fact>, Error>> apply(
      final FactSet facts,
      Long ruleOrigin,
      TrustedOrigins scope,
      SymbolTable symbolTable,
      StepBudget steps) {
    MatchedVariables variables = variablesSet();

    Combinator combinator = new Combinator(variables, this.body, facts, scope, symbolTable, steps);

    Spliterator<Result<Pair<Origin, Map<Long, Term>>, Error>> splitItr =
        Spliterators.spliteratorUnknownSize(combinator, Spliterator.ORDERED);
    Stream<Result<Pair<Origin, Map<Long, Term>>, Error>> stream =
        StreamSupport.stream(splitItr, false);

    return stream.flatMap(
        res -> {
          if (res.isErr()) {
            return Stream.of(Result.err(res.getErr()));
          }
          Pair<Origin, Map<Long, Term>> t = res.getOk();
          Origin origin = t._1;
          Map<Long, Term> generatedVariables = t._2;
          TemporarySymbolTable temporarySymbols = new TemporarySymbolTable(symbolTable);
          for (Expression e : this.expressions) {
            try {
              Term term = e.evaluate(generatedVariables, temporarySymbols, steps);

              if (term instanceof Term.Bool) {
                Term.Bool b = (Term.Bool) term;
                if (!b.value()) {
                  return Stream.empty();
                }
                // continue evaluating if true
              } else {
                return Stream.of(Result.err(new Error.InvalidType()));
              }
            } catch (Error error) {
              return Stream.of(Result.err(error));
            }
          }

          Predicate p = this.head.clone();
          for (int index = 0; index < p.terms().size(); index++) {
            if (p.terms().get(index) instanceof Term.Variable) {
              Term.Variable var = (Term.Variable) p.terms().get(index);
              if (!generatedVariables.containsKey(var.value())) {
                // throw new Error("variables that appear in the head should appear in the body
                // as well");
                return Stream.of(Result.err(new Error.InternalError()));
              }
              p.terms().set(index, generatedVariables.get(var.value()));
            }
          }

          origin.add(ruleOrigin);
          return Stream.of(Result.ok(new Pair<>(origin, new Fact(p))));
        });
  }

  private MatchedVariables variablesSet() {
    final Set<Long> variablesSet = new HashSet<>();

    for (final Predicate pred : this.body) {
      variablesSet.addAll(
          pred.terms().stream()
              .filter((id) -> id instanceof Term.Variable)
              .map((id) -> ((Term.Variable) id).value())
              .collect(Collectors.toSet()));
    }
    return new MatchedVariables(variablesSet);
  }

  // do not produce new facts, only find one matching set of facts
  public boolean findMatch(
      final FactSet facts,
      Long origin,
      TrustedOrigins scope,
      SymbolTable symbolTable,
      StepBudget steps)
      throws Error {
    MatchedVariables variables = variablesSet();

    if (this.body.isEmpty()) {
      return variables.checkExpressions(this.expressions, symbolTable, steps).isPresent();
    }

    var stream = this.apply(facts, origin, scope, symbolTable, steps);
    var it = stream.iterator();

    if (!it.hasNext()) {
      return false;
    }

    var next = it.next();
    if (next.isOk()) {
      return true;
    } else {
      throw next.getErr();
    }
  }

  // verifies that the expressions return true for every matching set of facts
  public boolean checkMatchAll(
      final FactSet facts, TrustedOrigins scope, SymbolTable symbolTable, StepBudget steps)
      throws Error {
    MatchedVariables variables = variablesSet();

    if (this.body.isEmpty()) {
      return variables.checkExpressions(this.expressions, symbolTable, steps).isPresent();
    }

    Combinator combinator = new Combinator(variables, this.body, facts, scope, symbolTable, steps);

    boolean found = false;

    for (Combinator it = combinator; it.hasNext(); ) {
      Result<Pair<Origin, Map<Long, Term>>, Error> res = it.next();
      if (res.isErr()) {
        throw res.getErr();
      }
      Pair<Origin, Map<Long, Term>> t = res.getOk();
      Map<Long, Term> generatedVariables = t._2;
      found = true;

      TemporarySymbolTable temporarySymbols = new TemporarySymbolTable(symbolTable);
      for (Expression e : this.expressions) {

        Term term = e.evaluate(generatedVariables, temporarySymbols, steps);
        if (term instanceof Term.Bool) {
          Term.Bool b = (Term.Bool) term;
          if (!b.value()) {
            return false;
          }
          // continue evaluating if true
        } else {
          throw new Error.InvalidType();
        }
      }
    }

    return found;
  }

  public Rule(
      final Predicate head, final List<Predicate> body, final List<Expression> expressions) {
    this.head = head;
    this.body = body;
    this.expressions = expressions;
    this.scopes = new ArrayList<>();
  }

  public Rule(
      final Predicate head,
      final List<Predicate> body,
      final List<Expression> expressions,
      final List<Scope> scopes) {
    this.head = head;
    this.body = body;
    this.expressions = expressions;
    this.scopes = scopes;
  }

  public Schema.Rule serialize() {
    Schema.Rule.Builder b = Schema.Rule.newBuilder().setHead(this.head.serialize());

    for (Predicate predicate : this.body) {
      b.addBody(predicate.serialize());
    }

    for (Expression expression : this.expressions) {
      b.addExpressions(expression.serialize());
    }

    for (Scope scope : this.scopes) {
      b.addScope(scope.serialize());
    }

    return b.build();
  }

  public static Result<Rule, Error.FormatError> deserialize(
      Schema.Rule rule, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
    if (rule.getBodyCount() > limits.getMaxPredicatesPerBody()) {
      return Result.err(
          new Error.FormatError.DeserializationLimitError(
              Error.FormatError.DeserializationLimitError.Reason.TOO_MANY_PREDICATES));
    }
    if (rule.getExpressionsCount() > limits.getMaxExpressionsPerBody()) {
      return Result.err(
          new Error.FormatError.DeserializationLimitError(
              Error.FormatError.DeserializationLimitError.Reason.TOO_MANY_EXPRESSIONS));
    }

    ArrayList<Predicate> body = new ArrayList<>();
    for (Schema.Predicate predicate : rule.getBodyList()) {
      var res = Predicate.deserialize(predicate, limits, symbols);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        body.add(res.getOk());
      }
    }

    ArrayList<Expression> expressions = new ArrayList<>();
    for (Schema.Expression expression : rule.getExpressionsList()) {
      var res = Expression.deserialize(expression, limits, symbols);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        expressions.add(res.getOk());
      }
    }

    ArrayList<Scope> scopes = new ArrayList<>();
    for (Schema.Scope scope : rule.getScopeList()) {
      var res = Scope.deserialize(scope, limits, symbols);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        scopes.add(res.getOk());
      }
    }

    var res = Predicate.deserialize(rule.getHead(), limits, symbols);
    if (res.isErr()) {
      Error.FormatError e = res.getErr();
      return Result.err(e);
    } else {
      return Result.ok(new Rule(res.getOk(), body, expressions, scopes));
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

    Rule rule = (Rule) o;

    if (!Objects.equals(head, rule.head)) {
      return false;
    }
    if (!Objects.equals(body, rule.body)) {
      return false;
    }
    if (!Objects.equals(expressions, rule.expressions)) {
      return false;
    }
    return Objects.equals(scopes, rule.scopes);
  }

  @Override
  public int hashCode() {
    int result = head != null ? head.hashCode() : 0;
    result = 31 * result + (body != null ? body.hashCode() : 0);
    result = 31 * result + (expressions != null ? expressions.hashCode() : 0);
    result = 31 * result + (scopes != null ? scopes.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "Rule{"
        + "head="
        + head
        + ", body="
        + body
        + ", expressions="
        + expressions
        + ", scopes="
        + scopes
        + '}';
  }
}
