/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.util.List;
import java.util.Optional;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.expressions.Expression;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.format.SerializedBiscuit;

public final class SchemaVersion {
  private final boolean containsScopes;
  private final boolean containsV31;
  private final boolean containsCheckAll;
  private final boolean containsV33;
  private final boolean containsExternalKey;

  public SchemaVersion(
      List<Fact> facts,
      List<Rule> rules,
      List<Check> checks,
      List<Scope> scopes,
      Optional<PublicKey> externalKey) {
    containsScopes =
        !scopes.isEmpty()
            || rules.stream().anyMatch(r -> !r.scopes().isEmpty())
            || checks.stream()
                .anyMatch(c -> c.queries().stream().anyMatch(q -> !q.scopes().isEmpty()));

    containsCheckAll = checks.stream().anyMatch(c -> c.kind() == Check.Kind.ALL);

    containsV31 =
        rules.stream().anyMatch(r -> containsV31Op(r.expressions()))
            || checks.stream()
                .anyMatch(c -> c.queries().stream().anyMatch(q -> containsV31Op(q.expressions())));

    containsV33 =
        checks.stream().anyMatch(c -> c.kind() == Check.Kind.REJECT)
            || rules.stream()
                .anyMatch(
                    r ->
                        containsV33Predicate(r.head())
                            || r.body().stream().anyMatch(SchemaVersion::containsV33Predicate)
                            || containsV33Op(r.expressions()))
            || checks.stream()
                .anyMatch(
                    c ->
                        c.queries().stream()
                            .anyMatch(
                                q ->
                                    q.body().stream().anyMatch(SchemaVersion::containsV33Predicate)
                                        || containsV33Op(q.expressions())))
            || facts.stream().anyMatch(f -> containsV33Predicate(f.predicate()));

    containsExternalKey = externalKey.isPresent();
  }

  public int version() {
    if (containsV33) {
      return SerializedBiscuit.DATALOG_3_3;
    }
    if (containsExternalKey) {
      return SerializedBiscuit.DATALOG_3_2;
    }
    if (containsScopes || containsV31 || containsCheckAll) {
      return SerializedBiscuit.DATALOG_3_1;
    }
    return SerializedBiscuit.MIN_SCHEMA_VERSION;
  }

  public Result<Void, Error.FormatError> checkCompatibility(int version) {
    if (version < SerializedBiscuit.DATALOG_3_1) {
      if (containsScopes) {
        return Result.err(
            new Error.FormatError.DeserializationError(
                "scopes are only supported in datalog v3.1+"));
      }
      if (containsV31) {
        return Result.err(
            new Error.FormatError.DeserializationError(
                "bitwise operators and != are only supported in datalog v3.1+"));
      }
      if (containsCheckAll) {
        return Result.err(
            new Error.FormatError.DeserializationError(
                "check all is only supported in datalog v3.1+"));
      }
    }
    if (version < SerializedBiscuit.DATALOG_3_2 && containsExternalKey) {
      return Result.err(
          new Error.FormatError.DeserializationError(
              "third-party blocks are only supported in datalog v3.2+"));
    }

    if (version < SerializedBiscuit.DATALOG_3_3 && containsV33) {
      return Result.err(
          new Error.FormatError.DeserializationError(
              "maps, arrays, null, closures are only supported in datalog v3.3+"));
    }
    return Result.ok(null);
  }

  private static boolean containsV31Op(List<Expression> expressions) {
    for (Expression e : expressions) {
      for (Op op : e.getOps()) {
        if (op instanceof Op.Binary) {
          Op.Binary b = (Op.Binary) op;
          switch (b.getOp()) {
            case BitwiseAnd:
            case BitwiseOr:
            case BitwiseXor:
            case NotEqual:
              return true;
            default:
          }
        }
      }
    }
    return false;
  }

  private static boolean containsV33Op(List<Expression> expressions) {
    for (Expression e : expressions) {
      for (Op op : e.getOps()) {
        if (op instanceof Op.Unary) {
          Op.Unary b = (Op.Unary) op;
          switch (b.getOp()) {
            case TypeOf:
              return true;
            default:
          }
        } else if (op instanceof Op.Binary) {
          Op.Binary b = (Op.Binary) op;
          switch (b.getOp()) {
            case HeterogeneousEqual:
            case HeterogeneousNotEqual:
            case LazyAnd:
            case LazyOr:
            case Get:
            case Any:
            case All:
            case TryOr:
              return true;
            default:
          }
        } else if (op instanceof Op.Closure) {
          return true;
        } else if (op instanceof Term.Null) {
          return true;
        } else if (op instanceof Term.Array) {
          return true;
        } else if (op instanceof Term.Map) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean containsV33Predicate(Predicate predicate) {
    return predicate.terms().stream().anyMatch(SchemaVersion::containsV33Term);
  }

  private static boolean containsV33Term(Term term) {
    if (term instanceof Term.Null) {
      return true;
    }
    if (term instanceof Term.Array) {
      return true;
    }
    if (term instanceof Term.Map) {
      return true;
    }
    return false;
  }
}
