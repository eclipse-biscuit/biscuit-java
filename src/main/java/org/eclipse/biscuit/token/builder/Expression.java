/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;

public abstract class Expression {

  public final org.eclipse.biscuit.datalog.expressions.Expression convertExpr(
      SymbolTable symbolTable) {
    ArrayList<Op> ops = new ArrayList<>();
    this.toOpcodes(symbolTable, ops);

    return new org.eclipse.biscuit.datalog.expressions.Expression(ops);
  }

  public static Expression convertFrom(ArrayList<Op> ops, SymbolTable symbolTable) {
    Deque<Expression> stack = new ArrayDeque<Expression>(16);
    for (Op op : ops) {
      if (op instanceof org.eclipse.biscuit.datalog.Term) {
        org.eclipse.biscuit.datalog.Term v = (org.eclipse.biscuit.datalog.Term) op;
        stack.push(Term.convertFrom(v, symbolTable));
      } else if (op instanceof Op.Closure) {
        Op.Closure closure = (Op.Closure) op;
        stack.push(closure.toExpression(symbolTable));
      } else if (op instanceof Op.Unary) {
        Op.Unary v = (Op.Unary) op;
        Expression e1 = stack.pop();

        switch (v.getOp()) {
          case Length:
            stack.push(new Expression.Unary(OpCode.Length, e1));
            break;
          case Negate:
            stack.push(new Expression.Unary(OpCode.Negate, e1));
            break;
          case Parens:
            stack.push(new Expression.Unary(OpCode.Parens, e1));
            break;
          case TypeOf:
            stack.push(new Expression.Unary(OpCode.TypeOf, e1));
            break;
          default:
            return null;
        }
      } else if (op instanceof Op.Binary) {
        Op.Binary v = (Op.Binary) op;
        Expression e2 = stack.pop();
        Expression e1 = stack.pop();

        switch (v.getOp()) {
          case LessThan:
            stack.push(new Expression.Binary(OpCode.LessThan, e1, e2));
            break;
          case GreaterThan:
            stack.push(new Expression.Binary(OpCode.GreaterThan, e1, e2));
            break;
          case LessOrEqual:
            stack.push(new Expression.Binary(OpCode.LessOrEqual, e1, e2));
            break;
          case GreaterOrEqual:
            stack.push(new Expression.Binary(OpCode.GreaterOrEqual, e1, e2));
            break;
          case Equal:
            stack.push(new Expression.Binary(OpCode.Equal, e1, e2));
            break;
          case NotEqual:
            stack.push(new Expression.Binary(OpCode.NotEqual, e1, e2));
            break;
          case HeterogeneousEqual:
            stack.push(new Expression.Binary(OpCode.HeterogeneousEqual, e1, e2));
            break;
          case HeterogeneousNotEqual:
            stack.push(new Expression.Binary(OpCode.HeterogeneousNotEqual, e1, e2));
            break;
          case Contains:
            stack.push(new Expression.Binary(OpCode.Contains, e1, e2));
            break;
          case Prefix:
            stack.push(new Expression.Binary(OpCode.Prefix, e1, e2));
            break;
          case Suffix:
            stack.push(new Expression.Binary(OpCode.Suffix, e1, e2));
            break;
          case Regex:
            stack.push(new Expression.Binary(OpCode.Regex, e1, e2));
            break;
          case Add:
            stack.push(new Expression.Binary(OpCode.Add, e1, e2));
            break;
          case Sub:
            stack.push(new Expression.Binary(OpCode.Sub, e1, e2));
            break;
          case Mul:
            stack.push(new Expression.Binary(OpCode.Mul, e1, e2));
            break;
          case Div:
            stack.push(new Expression.Binary(OpCode.Div, e1, e2));
            break;
          case And:
            stack.push(new Expression.Binary(OpCode.And, e1, e2));
            break;
          case Or:
            stack.push(new Expression.Binary(OpCode.Or, e1, e2));
            break;
          case LazyAnd:
            stack.push(new Expression.Binary(OpCode.LazyAnd, e1, e2));
            break;
          case LazyOr:
            stack.push(new Expression.Binary(OpCode.LazyOr, e1, e2));
            break;
          case Intersection:
            stack.push(new Expression.Binary(OpCode.Intersection, e1, e2));
            break;
          case Union:
            stack.push(new Expression.Binary(OpCode.Union, e1, e2));
            break;
          case BitwiseAnd:
            stack.push(new Expression.Binary(OpCode.BitwiseAnd, e1, e2));
            break;
          case BitwiseOr:
            stack.push(new Expression.Binary(OpCode.BitwiseOr, e1, e2));
            break;
          case BitwiseXor:
            stack.push(new Expression.Binary(OpCode.BitwiseXor, e1, e2));
            break;
          case Get:
            stack.push(new Expression.Binary(OpCode.Get, e1, e2));
            break;
          case Any:
            stack.push(new Expression.Binary(OpCode.Any, e1, e2));
            break;
          case All:
            stack.push(new Expression.Binary(OpCode.All, e1, e2));
            break;
          case TryOr:
            stack.push(new Expression.Binary(OpCode.TryOr, e1, e2));
            break;
          default:
            return null;
        }
      }
    }

    return stack.pop();
  }

  public abstract void toOpcodes(SymbolTable symbolTable, List<Op> ops);

  public abstract void gatherVariables(Set<String> variables) throws Error.Shadowing;

  public enum OpCode {
    Negate,
    Parens,
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Equal,
    NotEqual,
    HeterogeneousEqual,
    HeterogeneousNotEqual,
    Contains,
    Prefix,
    Suffix,
    Regex,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    LazyAnd,
    LazyOr,
    Length,
    Intersection,
    Union,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    TypeOf,
    Get,
    Any,
    All,
    TryOr,
  }

  public static final class Unary extends Expression {
    private final OpCode op;
    private final Expression arg1;

    public Unary(OpCode op, Expression arg1) {
      this.op = op;
      this.arg1 = arg1;
    }

    public void toOpcodes(SymbolTable symbolTable, List<Op> ops) {
      this.arg1.toOpcodes(symbolTable, ops);

      switch (this.op) {
        case Negate:
          ops.add(new Op.Unary(Op.UnaryOp.Negate));
          break;
        case Parens:
          ops.add(new Op.Unary(Op.UnaryOp.Parens));
          break;
        case Length:
          ops.add(new Op.Unary(Op.UnaryOp.Length));
          break;
        case TypeOf:
          ops.add(new Op.Unary(Op.UnaryOp.TypeOf));
          break;
        default:
          throw new RuntimeException("unmapped ops: " + this.op);
      }
    }

    public void gatherVariables(Set<String> variables) throws Error.Shadowing {
      this.arg1.gatherVariables(variables);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Unary unary = (Unary) o;

      if (op != unary.op) {
        return false;
      }
      return arg1.equals(unary.arg1);
    }

    @Override
    public int hashCode() {
      int result = op.hashCode();
      result = 31 * result + arg1.hashCode();
      return result;
    }

    @Override
    public String toString() {
      switch (op) {
        case Negate:
          return "!" + arg1;
        case Parens:
          return "(" + arg1 + ")";
        case Length:
          return arg1.toString() + ".length()";
        case TypeOf:
          return arg1.toString() + ".type()";
        default:
          return "";
      }
    }
  }

  public static final class Binary extends Expression {
    private final OpCode op;
    private final Expression arg1;
    private final Expression arg2;

    public Binary(OpCode op, Expression arg1, Expression arg2) {
      this.op = op;
      this.arg1 = arg1;
      this.arg2 = arg2;
    }

    public void toOpcodes(SymbolTable symbolTable, List<Op> ops) {
      this.arg1.toOpcodes(symbolTable, ops);
      this.arg2.toOpcodes(symbolTable, ops);

      switch (this.op) {
        case LessThan:
          ops.add(new Op.Binary(Op.BinaryOp.LessThan));
          break;
        case GreaterThan:
          ops.add(new Op.Binary(Op.BinaryOp.GreaterThan));
          break;
        case LessOrEqual:
          ops.add(new Op.Binary(Op.BinaryOp.LessOrEqual));
          break;
        case GreaterOrEqual:
          ops.add(new Op.Binary(Op.BinaryOp.GreaterOrEqual));
          break;
        case Equal:
          ops.add(new Op.Binary(Op.BinaryOp.Equal));
          break;
        case NotEqual:
          ops.add(new Op.Binary(Op.BinaryOp.NotEqual));
          break;
        case HeterogeneousEqual:
          ops.add(new Op.Binary(Op.BinaryOp.HeterogeneousEqual));
          break;
        case HeterogeneousNotEqual:
          ops.add(new Op.Binary(Op.BinaryOp.HeterogeneousNotEqual));
          break;
        case Contains:
          ops.add(new Op.Binary(Op.BinaryOp.Contains));
          break;
        case Prefix:
          ops.add(new Op.Binary(Op.BinaryOp.Prefix));
          break;
        case Suffix:
          ops.add(new Op.Binary(Op.BinaryOp.Suffix));
          break;
        case Regex:
          ops.add(new Op.Binary(Op.BinaryOp.Regex));
          break;
        case Add:
          ops.add(new Op.Binary(Op.BinaryOp.Add));
          break;
        case Sub:
          ops.add(new Op.Binary(Op.BinaryOp.Sub));
          break;
        case Mul:
          ops.add(new Op.Binary(Op.BinaryOp.Mul));
          break;
        case Div:
          ops.add(new Op.Binary(Op.BinaryOp.Div));
          break;
        case And:
          ops.add(new Op.Binary(Op.BinaryOp.And));
          break;
        case Or:
          ops.add(new Op.Binary(Op.BinaryOp.Or));
          break;
        case LazyAnd:
          ops.add(new Op.Binary(Op.BinaryOp.LazyAnd));
          break;
        case LazyOr:
          ops.add(new Op.Binary(Op.BinaryOp.LazyOr));
          break;
        case Intersection:
          ops.add(new Op.Binary(Op.BinaryOp.Intersection));
          break;
        case Union:
          ops.add(new Op.Binary(Op.BinaryOp.Union));
          break;
        case BitwiseAnd:
          ops.add(new Op.Binary(Op.BinaryOp.BitwiseAnd));
          break;
        case BitwiseOr:
          ops.add(new Op.Binary(Op.BinaryOp.BitwiseOr));
          break;
        case BitwiseXor:
          ops.add(new Op.Binary(Op.BinaryOp.BitwiseXor));
          break;
        case Get:
          ops.add(new Op.Binary(Op.BinaryOp.Get));
          break;
        case Any:
          ops.add(new Op.Binary(Op.BinaryOp.Any));
          break;
        case All:
          ops.add(new Op.Binary(Op.BinaryOp.All));
          break;
        case TryOr:
          ops.add(new Op.Binary(Op.BinaryOp.TryOr));
          break;
        default:
          throw new RuntimeException("unmapped ops: " + this.op);
      }
    }

    public void gatherVariables(Set<String> variables) throws Error.Shadowing {
      this.arg1.gatherVariables(variables);
      this.arg2.gatherVariables(variables);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Binary binary = (Binary) o;

      if (op != binary.op) {
        return false;
      }
      if (!arg1.equals(binary.arg1)) {
        return false;
      }
      return arg2.equals(binary.arg2);
    }

    @Override
    public int hashCode() {
      int result = op.hashCode();
      result = 31 * result + arg1.hashCode();
      result = 31 * result + arg2.hashCode();
      return result;
    }

    @Override
    public String toString() {
      switch (op) {
        case LessThan:
          return arg1.toString() + " < " + arg2.toString();
        case GreaterThan:
          return arg1.toString() + " > " + arg2.toString();
        case LessOrEqual:
          return arg1.toString() + " <= " + arg2.toString();
        case GreaterOrEqual:
          return arg1.toString() + " >= " + arg2.toString();
        case Equal:
          return arg1.toString() + " === " + arg2.toString();
        case NotEqual:
          return arg1.toString() + " !== " + arg2.toString();
        case HeterogeneousEqual:
          return arg1.toString() + " == " + arg2.toString();
        case HeterogeneousNotEqual:
          return arg1.toString() + " != " + arg2.toString();
        case Contains:
          return arg1.toString() + ".contains(" + arg2.toString() + ")";
        case Prefix:
          return arg1.toString() + ".starts_with(" + arg2.toString() + ")";
        case Suffix:
          return arg1.toString() + ".ends_with(" + arg2.toString() + ")";
        case Regex:
          return arg1.toString() + ".matches(" + arg2.toString() + ")";
        case Add:
          return arg1.toString() + " + " + arg2.toString();
        case Sub:
          return arg1.toString() + " - " + arg2.toString();
        case Mul:
          return arg1.toString() + " * " + arg2.toString();
        case Div:
          return arg1.toString() + " / " + arg2.toString();
        case And:
          return arg1.toString() + " && " + arg2.toString();
        case Or:
          return arg1.toString() + " || " + arg2.toString();
        case LazyAnd:
          return arg1.toString() + " && " + arg2.toString();
        case LazyOr:
          return arg1.toString() + " || " + arg2.toString();
        case Intersection:
          return arg1.toString() + ".intersection(" + arg2.toString() + ")";
        case Union:
          return arg1.toString() + ".union(" + arg2.toString() + ")";
        case BitwiseAnd:
          return arg1.toString() + " & " + arg2.toString();
        case BitwiseOr:
          return arg1.toString() + " | " + arg2.toString();
        case BitwiseXor:
          return arg1.toString() + " ^ " + arg2.toString();
        case Get:
          return arg1.toString() + ".get(" + arg2.toString() + ")";
        case Any:
          return arg1.toString() + ".any(" + arg2.toString() + ")";
        case All:
          return arg1.toString() + ".all(" + arg2.toString() + ")";
        case TryOr:
          return arg1.toString() + ".try_or(" + arg2.toString() + ")";
        default:
          return "";
      }
    }
  }

  public static final class Closure extends Expression {
    private ArrayList<String> params;
    private Expression body;

    public Closure(Expression body) {
      this.params = new ArrayList<>();
      this.body = body;
    }

    public Closure(ArrayList<String> params, Expression body) {
      this.params = params;
      this.body = body;
    }

    public void toOpcodes(SymbolTable symbolTable, List<Op> ops) {
      ArrayList<Long> paramIndexes = new ArrayList<Long>();
      for (String param : params) {
        long index = symbolTable.insert(param);
        paramIndexes.add(new Long(index));
      }
      ArrayList<Op> bodyOps = new ArrayList<>();
      body.toOpcodes(symbolTable, bodyOps);
      ops.add(new Op.Closure(paramIndexes, bodyOps));
    }

    public void gatherVariables(Set<String> variables) throws Error.Shadowing {
      for (String param : params) {
        if (variables.contains(param)) {
          throw new Error.Shadowing();
        }
      }
      body.gatherVariables(variables);
      for (String param : params) {
        variables.remove(param);
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

      Closure closure = (Closure) o;

      if (params.size() != closure.params.size()) {
        return false;
      }

      for (int i = 0; i < params.size(); i++) {
        if (params.get(i) != closure.params.get(i)) {
          return false;
        }
      }

      return body.equals(closure.body);
    }

    @Override
    public String toString() {
      if (params.size() == 0) {
        return body.toString();
      }

      String s = null;
      for (String param : params) {
        if (s == null) {
          s = "$" + param;
        } else {
          s = s + ", $" + param;
        }
      }
      return s + " -> " + body.toString();
    }
  }
}
