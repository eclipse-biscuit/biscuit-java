/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog.expressions;

import biscuit.format.schema.Schema;
import java.io.UnsupportedEncodingException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.eclipse.biscuit.datalog.MapKey;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.TemporarySymbolTable;
import org.eclipse.biscuit.datalog.Term;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.regex.PatternMatcher;
import org.eclipse.biscuit.token.builder.Expression;

public abstract class Op {
  public abstract void evaluate(
      Deque<Op> stack, Map<Long, Term> variables, TemporarySymbolTable temporarySymbolTable)
      throws Error.Execution;

  public abstract String print(Deque<String> stack, SymbolTable symbols);

  public abstract Schema.Op serialize();

  public static Result<Op, Error.FormatError> deserializeV2(Schema.Op op) {
    if (op.hasValue()) {
      var res = Term.deserializeEnumV2(op.getValue());
      return res.isOk() ? Result.ok(res.getOk()) : Result.err(res.getErr());
    } else if (op.hasUnary()) {
      return Op.Unary.deserializeV2(op.getUnary());
    } else if (op.hasBinary()) {
      return Op.Binary.deserializeV1(op.getBinary());
    } else if (op.hasClosure()) {
      return Op.Closure.deserializeV1(op.getClosure());
    } else {
      return Result.err(new Error.FormatError.DeserializationError("invalid unary operation"));
    }
  }

  public enum UnaryOp {
    Negate,
    Parens,
    Length,
    TypeOf,
  }

  public static final class Unary extends Op {
    private final UnaryOp op;

    public Unary(UnaryOp op) {
      this.op = op;
    }

    public UnaryOp getOp() {
      return op;
    }

    @Override
    public void evaluate(
        Deque<Op> stack, Map<Long, Term> variables, TemporarySymbolTable temporarySymbolTable)
        throws Error.Execution {
      Op value = stack.pop();
      switch (this.op) {
        case Negate:
          if (value instanceof Term.Bool) {
            Term.Bool b = (Term.Bool) value;
            stack.push(new Term.Bool(!b.value()));
          } else {
            throw new Error.Execution("invalid type for negate op, expected boolean");
          }
          break;
        case Parens:
          stack.push(value);
          break;
        case Length:
          if (value instanceof Term.Str) {
            Optional<String> s = temporarySymbolTable.getSymbol((int) ((Term.Str) value).value());
            if (s.isEmpty()) {
              throw new Error.Execution("string not found in symbols for id" + value);
            } else {
              try {
                stack.push(new Term.Integer(s.get().getBytes("UTF-8").length));
              } catch (UnsupportedEncodingException e) {
                throw new Error.Execution("cannot calculate string length: " + e.toString());
              }
            }
          } else if (value instanceof Term.Bytes) {
            stack.push(new Term.Integer(((Term.Bytes) value).value().length));
          } else if (value instanceof Term.Set) {
            stack.push(new Term.Integer(((Term.Set) value).value().size()));
          } else if (value instanceof Term.Array) {
            stack.push(new Term.Integer(((Term.Array) value).value().size()));
          } else if (value instanceof Term.Map) {
            stack.push(new Term.Integer(((Term.Map) value).value().size()));
          } else {
            throw new Error.Execution("invalid type for length op");
          }
          break;
        case TypeOf:
          Term term = (Term) value;
          stack.push(new Term.Str(temporarySymbolTable.insert(term.typeOf())));
          break;
        default:
          throw new Error.Execution("invalid type for op " + this.op);
      }
    }

    @Override
    public String print(Deque<String> stack, SymbolTable symbolTable) {
      String prec = stack.pop();
      String s = "";
      switch (this.op) {
        case Negate:
          s = "!" + prec;
          stack.push(s);
          break;
        case Parens:
          s = "(" + prec + ")";
          stack.push(s);
          break;
        case Length:
          s = prec + ".length()";
          stack.push(s);
          break;
        case TypeOf:
          s = prec + ".type()";
          stack.push(s);
          break;
        default:
      }
      return s;
    }

    @Override
    public Schema.Op serialize() {
      Schema.Op.Builder b = Schema.Op.newBuilder();

      Schema.OpUnary.Builder b1 = Schema.OpUnary.newBuilder();

      switch (this.op) {
        case Negate:
          b1.setKind(Schema.OpUnary.Kind.Negate);
          break;
        case Parens:
          b1.setKind(Schema.OpUnary.Kind.Parens);
          break;
        case Length:
          b1.setKind(Schema.OpUnary.Kind.Length);
          break;
        case TypeOf:
          b1.setKind(Schema.OpUnary.Kind.TypeOf);
          break;
        default:
      }

      b.setUnary(b1.build());

      return b.build();
    }

    public static Result<Op, Error.FormatError> deserializeV2(Schema.OpUnary op) {
      switch (op.getKind()) {
        case Negate:
          return Result.ok(new Op.Unary(UnaryOp.Negate));
        case Parens:
          return Result.ok(new Op.Unary(UnaryOp.Parens));
        case Length:
          return Result.ok(new Op.Unary(UnaryOp.Length));
        case TypeOf:
          return Result.ok(new Op.Unary(UnaryOp.TypeOf));
        default:
      }

      return Result.err(new Error.FormatError.DeserializationError("invalid unary operation"));
    }

    @Override
    public String toString() {
      return "Unary." + op;
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

      return op == unary.op;
    }

    @Override
    public int hashCode() {
      return op.hashCode();
    }
  }

  public enum BinaryOp {
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
    Intersection,
    Union,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    Get,
    Any,
    All,
    TryOr,
  }

  public static final class Binary extends Op {
    private final BinaryOp op;

    public Binary(BinaryOp value) {
      this.op = value;
    }

    public BinaryOp getOp() {
      return op;
    }

    @Override
    public void evaluate(
        Deque<Op> stack, Map<Long, Term> variables, TemporarySymbolTable temporarySymbolTable)
        throws Error.Execution {
      Op right = stack.pop();
      Op left = stack.pop();

      switch (this.op) {
        case LessThan:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            stack.push(
                new Term.Bool(((Term.Integer) left).value() < ((Term.Integer) right).value()));
          }
          if (right instanceof Term.Date && left instanceof Term.Date) {
            stack.push(new Term.Bool(((Term.Date) left).value() < ((Term.Date) right).value()));
          }
          break;
        case GreaterThan:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            stack.push(
                new Term.Bool(((Term.Integer) left).value() > ((Term.Integer) right).value()));
          }
          if (right instanceof Term.Date && left instanceof Term.Date) {
            stack.push(new Term.Bool(((Term.Date) left).value() > ((Term.Date) right).value()));
          }
          break;
        case LessOrEqual:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            stack.push(
                new Term.Bool(((Term.Integer) left).value() <= ((Term.Integer) right).value()));
          }
          if (right instanceof Term.Date && left instanceof Term.Date) {
            stack.push(new Term.Bool(((Term.Date) left).value() <= ((Term.Date) right).value()));
          }
          break;
        case GreaterOrEqual:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            stack.push(
                new Term.Bool(((Term.Integer) left).value() >= ((Term.Integer) right).value()));
          }
          if (right instanceof Term.Date && left instanceof Term.Date) {
            stack.push(new Term.Bool(((Term.Date) left).value() >= ((Term.Date) right).value()));
          }
          break;
        case Equal:
          if (left instanceof Term && right instanceof Term) {
            if (left.getClass() == right.getClass()) {
              stack.push(new Term.Bool(left.equals(right)));
            } else {
              throw new Error.Execution(
                  Error.Execution.Kind.InvalidType, "cannot compare disparate types");
            }
          } else {
            throw new Error.Execution(Error.Execution.Kind.InvalidType, "cannot compare closures");
          }
          break;
        case NotEqual:
          if (left instanceof Term && right instanceof Term) {
            if (left.getClass() == right.getClass()) {
              stack.push(new Term.Bool(!left.equals(right)));
            } else {
              throw new Error.Execution(
                  Error.Execution.Kind.InvalidType, "cannot compare disparate types");
            }
          } else {
            throw new Error.Execution(Error.Execution.Kind.InvalidType, "cannot compare closures");
          }
          break;
        case HeterogeneousEqual:
          if (left instanceof Term && right instanceof Term) {
            stack.push(new Term.Bool(left.equals(right)));
          } else {
            throw new Error.Execution(Error.Execution.Kind.InvalidType, "cannot compare closures");
          }
          break;
        case HeterogeneousNotEqual:
          if (left instanceof Term && right instanceof Term) {
            stack.push(new Term.Bool(!left.equals(right)));
          } else {
            throw new Error.Execution(Error.Execution.Kind.InvalidType, "cannot compare closures");
          }
          break;
        case Contains:
          if (left instanceof Term.Set
              && (right instanceof Term.Integer
                  || right instanceof Term.Str
                  || right instanceof Term.Bytes
                  || right instanceof Term.Date
                  || right instanceof Term.Bool)) {

            stack.push(new Term.Bool(((Term.Set) left).value().contains(right)));
          }
          if (right instanceof Term.Set && left instanceof Term.Set) {
            Set<Term> leftSet = ((Term.Set) left).value();
            Set<Term> rightSet = ((Term.Set) right).value();
            stack.push(new Term.Bool(leftSet.containsAll(rightSet)));
          }
          if (left instanceof Term.Str && right instanceof Term.Str) {
            Optional<String> leftS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) left).value());
            Optional<String> rightS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) right).value());

            if (leftS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) left).value());
            }
            if (rightS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) right).value());
            }

            stack.push(new Term.Bool(leftS.get().contains(rightS.get())));
          }
          if (left instanceof Term.Array) {
            List<Term> array = ((Term.Array) left).value();
            stack.push(new Term.Bool(array.contains(right)));
          }
          if (left instanceof Term.Map) {
            HashMap<MapKey, Term> map = ((Term.Map) left).value();
            if (right instanceof MapKey) {
              MapKey key = (MapKey) right;
              stack.push(new Term.Bool(map.containsKey(key)));
            } else {
              stack.push(new Term.Bool(false));
            }
          }
          break;
        case Prefix:
          if (right instanceof Term.Str && left instanceof Term.Str) {
            Optional<String> leftS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) left).value());
            Optional<String> rightS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) right).value());
            if (leftS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) left).value());
            }
            if (rightS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) right).value());
            }

            stack.push(new Term.Bool(leftS.get().startsWith(rightS.get())));
          }
          if (left instanceof Term.Array && right instanceof Term.Array) {
            List<Term> leftArray = ((Term.Array) left).value();
            List<Term> rightArray = ((Term.Array) right).value();
            if (leftArray.size() < rightArray.size()) {
              stack.push(new Term.Bool(false));
            } else {
              stack.push(new Term.Bool(leftArray.subList(0, rightArray.size()).equals(rightArray)));
            }
          }
          break;
        case Suffix:
          if (right instanceof Term.Str && left instanceof Term.Str) {
            Optional<String> leftS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) left).value());
            Optional<String> rightS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) right).value());
            if (leftS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) left).value());
            }
            if (rightS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) right).value());
            }
            stack.push(new Term.Bool(leftS.get().endsWith(rightS.get())));
          }
          if (left instanceof Term.Array && right instanceof Term.Array) {
            List<Term> leftArray = ((Term.Array) left).value();
            List<Term> rightArray = ((Term.Array) right).value();
            if (leftArray.size() < rightArray.size()) {
              stack.push(new Term.Bool(false));
            } else {
              stack.push(
                  new Term.Bool(
                      leftArray
                          .subList(leftArray.size() - rightArray.size(), leftArray.size())
                          .equals(rightArray)));
            }
          }
          break;
        case Regex:
          if (right instanceof Term.Str && left instanceof Term.Str) {
            Optional<String> leftS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) left).value());
            Optional<String> rightS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) right).value());
            if (leftS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) left).value());
            }
            if (rightS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) right).value());
            }

            stack.push(new Term.Bool(PatternMatcher.create(rightS.get()).match(leftS.get())));
          }
          break;
        case Add:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            try {
              stack.push(
                  new Term.Integer(
                      Math.addExact(
                          ((Term.Integer) left).value(), ((Term.Integer) right).value())));
            } catch (ArithmeticException e) {
              throw new Error.Execution(Error.Execution.Kind.Overflow, "overflow");
            }
          }
          if (right instanceof Term.Str && left instanceof Term.Str) {
            Optional<String> leftS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) left).value());
            Optional<String> rightS =
                temporarySymbolTable.getSymbol((int) ((Term.Str) right).value());

            if (leftS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) left).value());
            }
            if (rightS.isEmpty()) {
              throw new Error.Execution(
                  "cannot find string in symbols for index " + ((Term.Str) right).value());
            }

            String concatenation = leftS.get() + rightS.get();
            long index = temporarySymbolTable.insert(concatenation);
            stack.push(new Term.Str(index));
          }
          break;
        case Sub:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            try {
              stack.push(
                  new Term.Integer(
                      Math.subtractExact(
                          ((Term.Integer) left).value(), ((Term.Integer) right).value())));
            } catch (ArithmeticException e) {
              throw new Error.Execution(Error.Execution.Kind.Overflow, "overflow");
            }
          }
          break;
        case Mul:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            try {
              stack.push(
                  new Term.Integer(
                      Math.multiplyExact(
                          ((Term.Integer) left).value(), ((Term.Integer) right).value())));
            } catch (ArithmeticException e) {
              throw new Error.Execution(Error.Execution.Kind.Overflow, "overflow");
            }
          }
          break;
        case Div:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            long rl = ((Term.Integer) right).value();
            if (rl != 0) {
              stack.push(new Term.Integer(((Term.Integer) left).value() / rl));
            }
          }
          break;
        case And:
          if (right instanceof Term.Bool && left instanceof Term.Bool) {
            stack.push(new Term.Bool(((Term.Bool) left).value() && ((Term.Bool) right).value()));
          }
          break;
        case Or:
          if (right instanceof Term.Bool && left instanceof Term.Bool) {
            stack.push(new Term.Bool(((Term.Bool) left).value() || ((Term.Bool) right).value()));
          }
          break;
        case LazyAnd:
          if (left instanceof Term.Bool && right instanceof Closure) {
            if (((Term.Bool) left).value()) {
              Closure closure = (Closure) right;
              Term result = closure.call(variables, temporarySymbolTable);
              if (result instanceof Term.Bool) {
                stack.push((Term.Bool) result);
              }
            } else {
              stack.push(new Term.Bool(false));
            }
          }
          break;
        case LazyOr:
          if (left instanceof Term.Bool && right instanceof Closure) {
            if (((Term.Bool) left).value()) {
              stack.push(new Term.Bool(true));
            } else {
              Closure closure = (Closure) right;
              Term result = closure.call(variables, temporarySymbolTable);
              if (result instanceof Term.Bool) {
                stack.push((Term.Bool) result);
              }
            }
          }
          break;
        case Intersection:
          if (right instanceof Term.Set && left instanceof Term.Set) {
            HashSet<Term> intersec = new HashSet<Term>();
            HashSet<Term> setRight = ((Term.Set) right).value();
            HashSet<Term> setLeft = ((Term.Set) left).value();
            for (Term locId : setRight) {
              if (setLeft.contains(locId)) {
                intersec.add(locId);
              }
            }
            stack.push(new Term.Set(intersec));
          }
          break;
        case Union:
          if (right instanceof Term.Set && left instanceof Term.Set) {
            HashSet<Term> union = new HashSet<Term>();
            HashSet<Term> setRight = ((Term.Set) right).value();
            HashSet<Term> setLeft = ((Term.Set) left).value();
            union.addAll(setRight);
            union.addAll(setLeft);
            stack.push(new Term.Set(union));
          }
          break;
        case BitwiseAnd:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            long r = ((Term.Integer) right).value();
            long l = ((Term.Integer) left).value();
            stack.push(new Term.Integer(r & l));
          }
          break;
        case BitwiseOr:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            long r = ((Term.Integer) right).value();
            long l = ((Term.Integer) left).value();
            stack.push(new Term.Integer(r | l));
          }
          break;
        case BitwiseXor:
          if (right instanceof Term.Integer && left instanceof Term.Integer) {
            long r = ((Term.Integer) right).value();
            long l = ((Term.Integer) left).value();
            stack.push(new Term.Integer(r ^ l));
          }
          break;
        case Get:
          if (right instanceof Term.Integer && left instanceof Term.Array) {
            int index = (int) ((Term.Integer) right).value();
            List<Term> array = ((Term.Array) left).value();
            if (index >= array.size() || index < 0) {
              stack.push(new Term.Null());
            } else {
              Term element = array.get(index);
              if (element != null) {
                stack.push(element);
              } else {
                stack.push(new Term.Null());
              }
            }
          }
          if (right instanceof MapKey && left instanceof Term.Map) {
            MapKey key = (MapKey) right;
            HashMap<MapKey, Term> map = ((Term.Map) left).value();
            Term value = map.get(key);
            if (value != null) {
              stack.push(value);
            } else {
              stack.push(new Term.Null());
            }
          }
          break;
        case Any:
          if (right instanceof Closure) {
            Closure closure = (Closure) right;
            boolean result = false;
            if (left instanceof Term.Array) {
              List<Term> array = ((Term.Array) left).value();
              for (Term elem : array) {
                Term returnValue = closure.call(elem, variables, temporarySymbolTable);
                if (!(returnValue instanceof Term.Bool)) {
                  throw new Error.Execution("any op did not evaluate to a boolean");
                }
                result = ((Term.Bool) returnValue).value();
                if (result) {
                  break;
                }
              }
            } else if (left instanceof Term.Set) {
              HashSet<Term> set = ((Term.Set) left).value();
              for (Term elem : set) {
                Term returnValue = closure.call(elem, variables, temporarySymbolTable);
                if (!(returnValue instanceof Term.Bool)) {
                  throw new Error.Execution("any op did not evaluate to a boolean");
                }
                result = ((Term.Bool) returnValue).value();
                if (result) {
                  break;
                }
              }
            } else if (left instanceof Term.Map) {
              HashMap<MapKey, Term> map = ((Term.Map) left).value();
              for (Map.Entry<MapKey, Term> entry : map.entrySet()) {
                List<Term> params = new ArrayList<>(List.of(entry.getKey(), entry.getValue()));
                Term returnValue =
                    closure.call(new Term.Array(params), variables, temporarySymbolTable);
                if (!(returnValue instanceof Term.Bool)) {
                  throw new Error.Execution("any op did not evaluate to a boolean");
                }
                result = ((Term.Bool) returnValue).value();
                if (result) {
                  break;
                }
              }
            } else {
              throw new Error.Execution("left operand of any op is not a collection");
            }
            stack.push(new Term.Bool(result));
          } else {
            throw new Error.Execution("right operand of any op is not a closure");
          }
          break;
        case All:
          if (right instanceof Closure) {
            Closure closure = (Closure) right;
            boolean result = true;
            if (left instanceof Term.Array) {
              List<Term> array = ((Term.Array) left).value();
              for (Term elem : array) {
                Term returnValue = closure.call(elem, variables, temporarySymbolTable);
                if (!(returnValue instanceof Term.Bool)) {
                  throw new Error.Execution("all op did not evaluate to a boolean");
                }
                result = ((Term.Bool) returnValue).value();
                if (!result) {
                  break;
                }
              }
            } else if (left instanceof Term.Set) {
              HashSet<Term> set = ((Term.Set) left).value();
              for (Term elem : set) {
                Term returnValue = closure.call(elem, variables, temporarySymbolTable);
                if (!(returnValue instanceof Term.Bool)) {
                  throw new Error.Execution("all op did not evaluate to a boolean");
                }
                result = ((Term.Bool) returnValue).value();
                if (!result) {
                  break;
                }
              }
            } else if (left instanceof Term.Map) {
              HashMap<MapKey, Term> map = ((Term.Map) left).value();
              for (Map.Entry<MapKey, Term> entry : map.entrySet()) {
                ArrayList<Term> params = new ArrayList<>(List.of(entry.getKey(), entry.getValue()));
                Term returnValue =
                    closure.call(new Term.Array(params), variables, temporarySymbolTable);
                if (!(returnValue instanceof Term.Bool)) {
                  throw new Error.Execution("all op did not evaluate to a boolean");
                }
                result = ((Term.Bool) returnValue).value();
                if (!result) {
                  break;
                }
              }
            } else {
              throw new Error.Execution("left operand of all op is not a collection");
            }
            stack.push(new Term.Bool(result));
          } else {
            throw new Error.Execution("right operand of all op is not a closure");
          }
          break;
        case TryOr:
          if (left instanceof Closure) {
            Closure closure = (Closure) left;
            try {
              Term leftValue = closure.call(variables, temporarySymbolTable);
              stack.push(leftValue);
            } catch (Error e) {
              stack.push(right);
            }
          }
          break;
        default:
          throw new Error.Execution("binary exec error for op" + this);
      }
    }

    @Override
    public String print(Deque<String> stack, SymbolTable symbolTable) {
      String right = stack.pop();
      String left = stack.pop();
      String s = "";
      switch (this.op) {
        case LessThan:
          s = left + " < " + right;
          stack.push(s);
          break;
        case GreaterThan:
          s = left + " > " + right;
          stack.push(s);
          break;
        case LessOrEqual:
          s = left + " <= " + right;
          stack.push(s);
          break;
        case GreaterOrEqual:
          s = left + " >= " + right;
          stack.push(s);
          break;
        case HeterogeneousEqual:
          s = left + " == " + right;
          stack.push(s);
          break;
        case HeterogeneousNotEqual:
          s = left + " != " + right;
          stack.push(s);
          break;
        case Equal:
          s = left + " === " + right;
          stack.push(s);
          break;
        case NotEqual:
          s = left + " !== " + right;
          stack.push(s);
          break;
        case Contains:
          s = left + ".contains(" + right + ")";
          stack.push(s);
          break;
        case Prefix:
          s = left + ".starts_with(" + right + ")";
          stack.push(s);
          break;
        case Suffix:
          s = left + ".ends_with(" + right + ")";
          stack.push(s);
          break;
        case Regex:
          s = left + ".matches(" + right + ")";
          stack.push(s);
          break;
        case Add:
          s = left + " + " + right;
          stack.push(s);
          break;
        case Sub:
          s = left + " - " + right;
          stack.push(s);
          break;
        case Mul:
          s = left + " * " + right;
          stack.push(s);
          break;
        case Div:
          s = left + " / " + right;
          stack.push(s);
          break;
        case And:
          s = left + " && " + right;
          stack.push(s);
          break;
        case Or:
          s = left + " || " + right;
          stack.push(s);
          break;
        case LazyAnd:
          s = left + " && " + right;
          stack.push(s);
          break;
        case LazyOr:
          s = left + " || " + right;
          stack.push(s);
          break;
        case Intersection:
          s = left + ".intersection(" + right + ")";
          stack.push(s);
          break;
        case Union:
          s = left + ".union(" + right + ")";
          stack.push(s);
          break;
        case BitwiseAnd:
          s = left + " & " + right;
          stack.push(s);
          break;
        case BitwiseOr:
          s = left + " | " + right;
          stack.push(s);
          break;
        case BitwiseXor:
          s = left + " ^ " + right;
          stack.push(s);
          break;
        case Get:
          s = left + ".get(" + right + ")";
          stack.push(s);
          break;
        case Any:
          s = left + ".any(" + right + ")";
          stack.push(s);
          break;
        case All:
          s = left + ".any(" + right + ")";
          stack.push(s);
          break;
        case TryOr:
          s = left + ".try_or(" + right + ")";
          stack.push(s);
          break;
        default:
      }

      return s;
    }

    @Override
    public Schema.Op serialize() {
      Schema.Op.Builder b = Schema.Op.newBuilder();

      Schema.OpBinary.Builder b1 = Schema.OpBinary.newBuilder();

      switch (this.op) {
        case LessThan:
          b1.setKind(Schema.OpBinary.Kind.LessThan);
          break;
        case GreaterThan:
          b1.setKind(Schema.OpBinary.Kind.GreaterThan);
          break;
        case LessOrEqual:
          b1.setKind(Schema.OpBinary.Kind.LessOrEqual);
          break;
        case GreaterOrEqual:
          b1.setKind(Schema.OpBinary.Kind.GreaterOrEqual);
          break;
        case Equal:
          b1.setKind(Schema.OpBinary.Kind.Equal);
          break;
        case NotEqual:
          b1.setKind(Schema.OpBinary.Kind.NotEqual);
          break;
        case HeterogeneousEqual:
          b1.setKind(Schema.OpBinary.Kind.HeterogeneousEqual);
          break;
        case HeterogeneousNotEqual:
          b1.setKind(Schema.OpBinary.Kind.HeterogeneousNotEqual);
          break;
        case Contains:
          b1.setKind(Schema.OpBinary.Kind.Contains);
          break;
        case Prefix:
          b1.setKind(Schema.OpBinary.Kind.Prefix);
          break;
        case Suffix:
          b1.setKind(Schema.OpBinary.Kind.Suffix);
          break;
        case Regex:
          b1.setKind(Schema.OpBinary.Kind.Regex);
          break;
        case Add:
          b1.setKind(Schema.OpBinary.Kind.Add);
          break;
        case Sub:
          b1.setKind(Schema.OpBinary.Kind.Sub);
          break;
        case Mul:
          b1.setKind(Schema.OpBinary.Kind.Mul);
          break;
        case Div:
          b1.setKind(Schema.OpBinary.Kind.Div);
          break;
        case And:
          b1.setKind(Schema.OpBinary.Kind.And);
          break;
        case Or:
          b1.setKind(Schema.OpBinary.Kind.Or);
          break;
        case LazyAnd:
          b1.setKind(Schema.OpBinary.Kind.LazyAnd);
          break;
        case LazyOr:
          b1.setKind(Schema.OpBinary.Kind.LazyOr);
          break;
        case Intersection:
          b1.setKind(Schema.OpBinary.Kind.Intersection);
          break;
        case Union:
          b1.setKind(Schema.OpBinary.Kind.Union);
          break;
        case BitwiseAnd:
          b1.setKind(Schema.OpBinary.Kind.BitwiseAnd);
          break;
        case BitwiseOr:
          b1.setKind(Schema.OpBinary.Kind.BitwiseOr);
          break;
        case BitwiseXor:
          b1.setKind(Schema.OpBinary.Kind.BitwiseXor);
          break;
        case Get:
          b1.setKind(Schema.OpBinary.Kind.Get);
          break;
        case Any:
          b1.setKind(Schema.OpBinary.Kind.Any);
          break;
        case All:
          b1.setKind(Schema.OpBinary.Kind.All);
          break;
        case TryOr:
          b1.setKind(Schema.OpBinary.Kind.Try);
          break;
        default:
      }

      b.setBinary(b1.build());

      return b.build();
    }

    public static Result<Op, Error.FormatError> deserializeV1(Schema.OpBinary op) {
      switch (op.getKind()) {
        case LessThan:
          return Result.ok(new Op.Binary(BinaryOp.LessThan));
        case GreaterThan:
          return Result.ok(new Op.Binary(BinaryOp.GreaterThan));
        case LessOrEqual:
          return Result.ok(new Op.Binary(BinaryOp.LessOrEqual));
        case GreaterOrEqual:
          return Result.ok(new Op.Binary(BinaryOp.GreaterOrEqual));
        case Equal:
          return Result.ok(new Op.Binary(BinaryOp.Equal));
        case NotEqual:
          return Result.ok(new Op.Binary(BinaryOp.NotEqual));
        case HeterogeneousEqual:
          return Result.ok(new Op.Binary(BinaryOp.HeterogeneousEqual));
        case HeterogeneousNotEqual:
          return Result.ok(new Op.Binary(BinaryOp.HeterogeneousNotEqual));
        case Contains:
          return Result.ok(new Op.Binary(BinaryOp.Contains));
        case Prefix:
          return Result.ok(new Op.Binary(BinaryOp.Prefix));
        case Suffix:
          return Result.ok(new Op.Binary(BinaryOp.Suffix));
        case Regex:
          return Result.ok(new Op.Binary(BinaryOp.Regex));
        case Add:
          return Result.ok(new Op.Binary(BinaryOp.Add));
        case Sub:
          return Result.ok(new Op.Binary(BinaryOp.Sub));
        case Mul:
          return Result.ok(new Op.Binary(BinaryOp.Mul));
        case Div:
          return Result.ok(new Op.Binary(BinaryOp.Div));
        case And:
          return Result.ok(new Op.Binary(BinaryOp.And));
        case Or:
          return Result.ok(new Op.Binary(BinaryOp.Or));
        case LazyAnd:
          return Result.ok(new Op.Binary(BinaryOp.LazyAnd));
        case LazyOr:
          return Result.ok(new Op.Binary(BinaryOp.LazyOr));
        case Intersection:
          return Result.ok(new Op.Binary(BinaryOp.Intersection));
        case Union:
          return Result.ok(new Op.Binary(BinaryOp.Union));
        case BitwiseAnd:
          return Result.ok(new Op.Binary(BinaryOp.BitwiseAnd));
        case BitwiseOr:
          return Result.ok(new Op.Binary(BinaryOp.BitwiseOr));
        case BitwiseXor:
          return Result.ok(new Op.Binary(BinaryOp.BitwiseXor));
        case Get:
          return Result.ok(new Op.Binary(BinaryOp.Get));
        case Any:
          return Result.ok(new Op.Binary(BinaryOp.Any));
        case All:
          return Result.ok(new Op.Binary(BinaryOp.All));
        case Try:
          return Result.ok(new Op.Binary(BinaryOp.TryOr));
        default:
          return Result.err(
              new Error.FormatError.DeserializationError(
                  "invalid binary operation: " + op.getKind()));
      }
    }

    @Override
    public String toString() {
      return "Binary." + op;
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

      return op == binary.op;
    }

    @Override
    public int hashCode() {
      return op.hashCode();
    }
  }

  public static final class Closure extends Op {
    private final ArrayList<Long> params;
    private final ArrayList<Op> ops;

    public Closure(ArrayList<Long> params, ArrayList<Op> ops) {
      this.params = params;
      this.ops = ops;
    }

    public void evaluate(
        Deque<Op> stack, Map<Long, Term> variables, TemporarySymbolTable temporarySymbolTable)
        throws Error.Execution {
      stack.push(this);
    }

    int arity() {
      return params.size();
    }

    Term call(Map<Long, Term> variables, TemporarySymbolTable temporarySymbolTable)
        throws Error.Execution {
      if (arity() != 0) {
        throw new Error.Execution("called closure with arity " + arity() + "with no arguments");
      }
      Deque<Op> stack = new ArrayDeque<Op>(16); // Default value
      for (Op op : ops) {
        op.evaluate(stack, variables, temporarySymbolTable);
      }
      if (stack.size() != 1) {
        throw new Error.Execution("invalid closure expression");
      }
      return (Term) stack.pop();
    }

    Term call(Term arg, Map<Long, Term> variables, TemporarySymbolTable temporarySymbolTable)
        throws Error.Execution {
      if (arity() != 1) {
        throw new Error.Execution("called closure with arity " + arity() + "with 1 argument");
      }
      if (variables.putIfAbsent(params.get(0), arg) != null) {
        throw new Error.Execution(
            Error.Execution.Kind.ShadowedVariable, "closure parameter shadows variable");
      }
      Deque<Op> stack = new ArrayDeque<Op>(16); // Default value
      for (Op op : ops) {
        op.evaluate(stack, variables, temporarySymbolTable);
      }
      variables.remove(params.get(0));
      if (stack.size() != 1) {
        throw new Error.Execution("invalid closure expression");
      }
      return (Term) stack.pop();
    }

    public String print(Deque<String> stack, SymbolTable symbols) {
      String paramNames = null;
      for (Long param : params) {
        String paramName = symbols.getSymbol(param.intValue()).get();
        if (paramNames == null) {
          paramNames = "$" + paramName;
        } else {
          paramNames = paramNames + ", $" + paramName;
        }
      }

      String s;
      Deque<String> bodyStack = new ArrayDeque<>();
      for (Op op : ops) {
        op.print(bodyStack, symbols);
      }
      if (paramNames == null) {
        s = bodyStack.remove();
      } else {
        s = paramNames + " -> " + bodyStack.remove();
      }
      stack.push(s);
      return s;
    }

    public Schema.Op serialize() {
      Schema.Op.Builder b = Schema.Op.newBuilder();
      Schema.OpClosure.Builder b1 = Schema.OpClosure.newBuilder();

      for (Long param : params) {
        b1.addParams(param.intValue());
      }

      for (Op op : this.ops) {
        b1.addOps(op.serialize());
      }

      b.setClosure(b1.build());

      return b.build();
    }

    public static Result<Op, Error.FormatError> deserializeV1(Schema.OpClosure closure) {
      ArrayList<Long> params = new ArrayList<>();
      ArrayList<Op> ops = new ArrayList<>();

      for (long param : closure.getParamsList()) {
        params.add(new Long(param));
      }

      for (Schema.Op op : closure.getOpsList()) {
        var res = Op.deserializeV2(op);
        if (res.isErr()) {
          return Result.err(res.getErr());
        } else {
          ops.add(res.getOk());
        }
      }

      return Result.ok(new Op.Closure(params, ops));
    }

    public Expression toExpression(SymbolTable symbols) {
      ArrayList<String> paramNames = new ArrayList<>();
      for (Long param : params) {
        paramNames.add(symbols.getSymbol(param.intValue()).get());
      }
      Expression body = Expression.convertFrom(ops, symbols);
      return new Expression.Closure(paramNames, body);
    }
  }
}
