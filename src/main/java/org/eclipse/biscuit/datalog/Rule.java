/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import io.vavr.Tuple2;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.eclipse.biscuit.datalog.expressions.Expression;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;

public final class Rule implements Serializable {
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

  public Stream<Result<Tuple2<Origin, Fact>, Error>> apply(
      final Supplier<Stream<Tuple2<Origin, Fact>>> factsSupplier,
      Long ruleOrigin,
      SymbolTable symbolTable) {
    MatchedVariables variables = variablesSet();

    Combinator combinator = new Combinator(variables, this.body, factsSupplier, symbolTable);
    Spliterator<Tuple2<Origin, Map<Long, Term>>> splitItr =
        Spliterators.spliteratorUnknownSize(combinator, Spliterator.ORDERED);
    Stream<Tuple2<Origin, Map<Long, Term>>> stream = StreamSupport.stream(splitItr, false);

    return stream
        .map(
            t -> {
              Origin origin = t._1;
              Map<Long, Term> generatedVariables = t._2;
              TemporarySymbolTable temporarySymbols = new TemporarySymbolTable(symbolTable);
              for (Expression e : this.expressions) {
                try {
                  Term term = e.evaluate(generatedVariables, temporarySymbols);

                  if (term instanceof Term.Bool) {
                    Term.Bool b = (Term.Bool) term;
                    if (!b.value()) {
                      return null;
                    }
                    // continue evaluating if true
                  } else {
                    return null;
                  }
                } catch (Error error) {
                  return null;
                }
              }

              Predicate p = this.head.clone();
              for (int index = 0; index < p.terms().size(); index++) {
                if (p.terms().get(index) instanceof Term.Variable) {
                  Term.Variable var = (Term.Variable) p.terms().get(index);
                  if (!generatedVariables.containsKey(var.value())) {
                    // throw new Error("variables that appear in the head should appear in the body
                    // as well");
                    return Result.<Tuple2<Origin, Fact>, Error>err(new Error.InternalError());
                  }
                  p.terms().set(index, generatedVariables.get(var.value()));
                }
              }

              origin.add(ruleOrigin);
              return Result.<Tuple2<Origin, Fact>, Error>ok(new Tuple2<>(origin, new Fact(p)));
            })
        .filter(Objects::nonNull);
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
      final FactSet facts, Long origin, TrustedOrigins scope, SymbolTable symbolTable)
      throws Error {
    MatchedVariables variables = variablesSet();

    if (this.body.isEmpty()) {
      return variables.checkExpressions(this.expressions, symbolTable).isPresent();
    }

    Supplier<Stream<Tuple2<Origin, Fact>>> factsSupplier = () -> facts.stream(scope);
    var stream = this.apply(factsSupplier, origin, symbolTable);
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
  public boolean checkMatchAll(final FactSet facts, TrustedOrigins scope, SymbolTable symbolTable)
      throws Error {
    MatchedVariables variables = variablesSet();

    if (this.body.isEmpty()) {
      return variables.checkExpressions(this.expressions, symbolTable).isPresent();
    }

    Supplier<Stream<Tuple2<Origin, Fact>>> factsSupplier = () -> facts.stream(scope);
    Combinator combinator = new Combinator(variables, this.body, factsSupplier, symbolTable);
    boolean found = false;

    for (Combinator it = combinator; it.hasNext(); ) {
      Tuple2<Origin, Map<Long, Term>> t = it.next();
      Map<Long, Term> generatedVariables = t._2;
      found = true;

      TemporarySymbolTable temporarySymbols = new TemporarySymbolTable(symbolTable);
      for (Expression e : this.expressions) {

        Term term = e.evaluate(generatedVariables, temporarySymbols);
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

  public Schema.RuleV2 serialize() {
    Schema.RuleV2.Builder b = Schema.RuleV2.newBuilder().setHead(this.head.serialize());

    for (int i = 0; i < this.body.size(); i++) {
      b.addBody(this.body.get(i).serialize());
    }

    for (int i = 0; i < this.expressions.size(); i++) {
      b.addExpressions(this.expressions.get(i).serialize());
    }

    for (Scope scope : this.scopes) {
      b.addScope(scope.serialize());
    }

    return b.build();
  }

  public static Result<Rule, Error.FormatError> deserializeV2(Schema.RuleV2 rule) {
    ArrayList<Predicate> body = new ArrayList<>();
    for (Schema.PredicateV2 predicate : rule.getBodyList()) {
      var res = Predicate.deserializeV2(predicate);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        body.add(res.getOk());
      }
    }

    ArrayList<Expression> expressions = new ArrayList<>();
    for (Schema.ExpressionV2 expression : rule.getExpressionsList()) {
      var res = Expression.deserializeV2(expression);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        expressions.add(res.getOk());
      }
    }

    ArrayList<Scope> scopes = new ArrayList<>();
    for (Schema.Scope scope : rule.getScopeList()) {
      var res = Scope.deserialize(scope);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        scopes.add(res.getOk());
      }
    }

    var res = Predicate.deserializeV2(rule.getHead());
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
