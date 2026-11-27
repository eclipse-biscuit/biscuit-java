/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import static biscuit.format.schema.Schema.Check.Kind.All;
import static biscuit.format.schema.Schema.Check.Kind.Reject;

import biscuit.format.schema.Schema;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.DeserializationLimit;

public final class Check {
  public enum Kind {
    ONE,
    ALL,
    REJECT
  }

  private static final int HASH_CODE_SEED = 31;

  private final Kind kind;

  private final List<Rule> queries;

  public Check(Kind kind, List<Rule> queries) {
    this.kind = kind;
    this.queries = queries;
  }

  public Kind kind() {
    return kind;
  }

  public List<Rule> queries() {
    return queries;
  }

  public Schema.Check serialize() {
    Schema.Check.Builder b = Schema.Check.newBuilder();

    // do not set the kind to One to keep compatibility with older library versions
    switch (this.kind) {
      case ALL:
        b.setKind(All);
        break;
      case REJECT:
        b.setKind(Reject);
        break;
      default:
    }

    for (Rule query : this.queries) {
      b.addQueries(query.serialize());
    }

    return b.build();
  }

  public static Result<Check, Error.FormatError> deserialize(
      Schema.Check check, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
    ArrayList<Rule> queries = new ArrayList<>();

    Kind kind;
    switch (check.getKind()) {
      case One:
        kind = Kind.ONE;
        break;
      case All:
        kind = Kind.ALL;
        break;
      case Reject:
        kind = Kind.REJECT;
        break;
      default:
        kind = Kind.ONE;
        break;
    }

    var allowedKinds = limits.getAllowedCheckKinds();
    if (allowedKinds != null && !allowedKinds.contains(kind)) {
      return Result.err(
          new Error.FormatError.DeserializationLimitError(
              Error.FormatError.DeserializationLimitError.Reason.CHECK_KIND_NOT_ALLOWED));
    }
    if (check.getQueriesCount() > limits.getMaxQueriesPerCheck()) {
      return Result.err(
          new Error.FormatError.DeserializationLimitError(
              Error.FormatError.DeserializationLimitError.Reason.TOO_MANY_QUERIES));
    }

    for (Schema.Rule query : check.getQueriesList()) {
      var res = Rule.deserialize(query, limits, symbols);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        queries.add(res.getOk());
      }
    }

    return Result.ok(new Check(kind, queries));
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

    if (kind != check.kind) {
      return false;
    }
    return Objects.equals(queries, check.queries);
  }

  @Override
  public int hashCode() {
    int result = kind != null ? kind.hashCode() : 0;
    result = HASH_CODE_SEED * result + (queries != null ? queries.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "Check{kind=" + kind + ", queries=" + queries + '}';
  }
}
