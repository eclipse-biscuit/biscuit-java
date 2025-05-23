/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

import biscuit.format.schema.Schema;
import io.vavr.control.Either;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import org.eclipse.biscuit.error.Error;

public final class Fact implements Serializable {
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

  public Schema.FactV2 serialize() {
    return Schema.FactV2.newBuilder().setPredicate(this.predicate.serialize()).build();
  }

  public static Either<Error.FormatError, Fact> deserializeV2(Schema.FactV2 fact) {
    Either<Error.FormatError, Predicate> res = Predicate.deserializeV2(fact.getPredicate());
    if (res.isLeft()) {
      Error.FormatError e = res.getLeft();
      return Left(e);
    } else {
      return Right(new Fact(res.get()));
    }
  }
}
