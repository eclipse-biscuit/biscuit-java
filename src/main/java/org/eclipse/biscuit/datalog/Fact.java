/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;

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

  public static Result<Fact, Error.FormatError> deserializeV2(Schema.FactV2 fact) {
    var res = Predicate.deserializeV2(fact.getPredicate());
    if (res.isErr()) {
      return Result.err(res.getErr());
    } else {
      return Result.ok(new Fact(res.getOk()));
    }
  }
}
