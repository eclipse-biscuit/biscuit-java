/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog.expressions;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

import biscuit.format.schema.Schema;
import io.vavr.control.Either;
import io.vavr.control.Option;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Map;
import java.util.Objects;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.TemporarySymbolTable;
import org.eclipse.biscuit.datalog.Term;
import org.eclipse.biscuit.error.Error;

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

  public Option<String> print(SymbolTable symbolTable) {
    Deque<String> stack = new ArrayDeque<>();
    for (Op op : ops) {
      op.print(stack, symbolTable);
    }
    if (stack.size() == 1) {
      return Option.some(stack.remove());
    } else {
      return Option.none();
    }
  }

  public Schema.ExpressionV2 serialize() {
    Schema.ExpressionV2.Builder b = Schema.ExpressionV2.newBuilder();

    for (Op op : this.ops) {
      b.addOps(op.serialize());
    }

    return b.build();
  }

  public static Either<Error.FormatError, Expression> deserializeV2(Schema.ExpressionV2 e) {
    ArrayList<Op> ops = new ArrayList<>();

    for (Schema.Op op : e.getOpsList()) {
      Either<Error.FormatError, Op> res = Op.deserializeV2(op);

      if (res.isLeft()) {
        Error.FormatError err = res.getLeft();
        return Left(err);
      } else {
        ops.add(res.get());
      }
    }

    return Right(new Expression(ops));
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
