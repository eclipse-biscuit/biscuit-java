/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.DeserializationLimit;

public final class Fact {
  private final Predicate predicate;

  public Predicate predicate() {
    return this.predicate;
  }

  public boolean matchPredicate(final Predicate rulePredicate) {
    return this.predicate.match(rulePredicate);
  }

  public Fact(final Predicate predicate) {
    this.predicate = predicate;
  }

  public Fact(final long name, final List<Term> terms) {
    this.predicate = new Predicate(name, terms);
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
    return Objects.equals(predicate, fact.predicate);
  }

  @Override
  public int hashCode() {
    return Objects.hash(predicate);
  }

  @Override
  public String toString() {
    return this.predicate.toString();
  }

  public Schema.Fact serialize() {
    return Schema.Fact.newBuilder().setPredicate(this.predicate.serialize()).build();
  }

  public static Comparator<Fact> comparator =
      Comparator.comparing(Fact::predicate, Predicate.comparator);

  public static Result<Fact, Error.FormatError> deserialize(
      Schema.Fact fact, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
    var res = Predicate.deserialize(fact.getPredicate(), limits, symbols);
    if (res.isErr()) {
      return Result.err(res.getErr());
    } else {
      return Result.ok(new Fact(res.getOk()));
    }
  }
}
