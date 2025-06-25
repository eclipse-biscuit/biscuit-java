/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import static biscuit.format.schema.Schema.CheckV2.Kind.All;

import biscuit.format.schema.Schema;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;

public final class Check {
  public enum Kind {
    ONE,
    ALL
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

  public Schema.CheckV2 serialize() {
    Schema.CheckV2.Builder b = Schema.CheckV2.newBuilder();

    // do not set the kind to One to keep compatibility with older library versions
    switch (this.kind) {
      case ALL:
        b.setKind(All);
        break;
      default:
    }

    for (int i = 0; i < this.queries.size(); i++) {
      b.addQueries(this.queries.get(i).serialize());
    }

    return b.build();
  }

  public static Result<Check, Error.FormatError> deserializeV2(Schema.CheckV2 check) {
    ArrayList<Rule> queries = new ArrayList<>();

    Kind kind;
    switch (check.getKind()) {
      case One:
        kind = Kind.ONE;
        break;
      case All:
        kind = Kind.ALL;
        break;
      default:
        kind = Kind.ONE;
        break;
    }

    for (Schema.RuleV2 query : check.getQueriesList()) {
      var res = Rule.deserializeV2(query);
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
