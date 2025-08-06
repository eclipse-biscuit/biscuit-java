/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog.expressions;

import biscuit.format.schema.Schema;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.TemporarySymbolTable;
import org.eclipse.biscuit.datalog.Term;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;

public final class Expression {
  private final ArrayList<Op> ops;

  public Expression(ArrayList<Op> ops) {
    this.ops = ops;
  }

  public ArrayList<Op> getOps() {
    return ops;
  }

  // FIXME: should return a Result<Term, error::Expression>
  public Term evaluate(Map<Long, Term> variables, TemporarySymbolTable temporarySymbolTable)
      throws Error.Execution {
    Deque<Term> stack = new ArrayDeque<Term>(16); // Default value
    for (Op op : ops) {
      op.evaluate(stack, variables, temporarySymbolTable);
    }
    if (stack.size() == 1) {
      return stack.pop();
    } else {
      throw new Error.Execution(this, "execution");
    }
  }

  public Optional<String> print(SymbolTable symbolTable) {
    Deque<String> stack = new ArrayDeque<>();
    for (Op op : ops) {
      op.print(stack, symbolTable);
    }
    if (stack.size() == 1) {
      return Optional.of(stack.remove());
    } else {
      return Optional.empty();
    }
  }

  public Schema.ExpressionV2 serialize() {
    Schema.ExpressionV2.Builder b = Schema.ExpressionV2.newBuilder();

    for (Op op : this.ops) {
      b.addOps(op.serialize());
    }

    return b.build();
  }

  public static Result<Expression, Error.FormatError> deserializeV2(Schema.ExpressionV2 e) {
    ArrayList<Op> ops = new ArrayList<>();

    for (Schema.Op op : e.getOpsList()) {
      var res = Op.deserializeV2(op);

      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        ops.add(res.getOk());
      }
    }

    return Result.ok(new Expression(ops));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Expression that = (Expression) o;

    return Objects.equals(ops, that.ops);
  }

  @Override
  public int hashCode() {
    return ops != null ? ops.hashCode() : 0;
  }

  @Override
  public String toString() {
    return "Expression{ops=" + ops + '}';
  }
}
