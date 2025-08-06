/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder.parser;

import static org.eclipse.biscuit.token.builder.parser.Parser.space;
import static org.eclipse.biscuit.token.builder.parser.Parser.term;

import org.eclipse.biscuit.datalog.Pair;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.builder.Expression;
import org.eclipse.biscuit.token.builder.Term;

public final class ExpressionParser {
  private ExpressionParser() {}

  public static Result<Pair<String, Expression>, Error> parse(String s) {
    return expr(space(s));
  }

  // Top-lever parser for an expression. Expression parsers are layered in
  // order to support operator precedence (see
  // https://en.wikipedia.org/wiki/Operator-precedence_parser).
  //
  // See https://github.com/biscuit-auth/biscuit/blob/master/SPECIFICATIONS.md#grammar
  // for the precedence order of operators in biscuit datalog.
  //
  // The operators with the lowest precedence are parsed at the outer level,
  // and their operands delegate to parsers that progressively handle more
  // tightly binding operators.
  //
  // This level handles the last operator in the precedence list: `||`
  // `||` is left associative, so multiple `||` expressions can be combined:
  // `a || b || c <=> (a || b) || c`
  public static Result<Pair<String, Expression>, Error> expr(String s) {
    var res1 = expr1(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      var res2 = binaryOp0(s);
      if (res2.isErr()) {
        break;
      }
      Pair<String, Expression.Op> t2 = res2.getOk();
      s = t2._1;

      s = space(s);

      var res3 = expr1(s);
      if (res3.isErr()) {
        return Result.err(res3.getErr());
      }
      Pair<String, Expression> t3 = res3.getOk();

      s = t3._1;
      Expression e2 = t3._2;
      Expression.Op op = t2._2;
      e = new Expression.Binary(op, e, e2);
    }

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles `&&`
  /// `&&` is left associative, so multiple `&&` expressions can be combined:
  /// `a && b && c <=> (a && b) && c`
  public static Result<Pair<String, Expression>, Error> expr1(String s) {
    var res1 = expr2(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      var res2 = binaryOp1(s);
      if (res2.isErr()) {
        break;
      }
      Pair<String, Expression.Op> t2 = res2.getOk();
      s = t2._1;

      s = space(s);

      var res3 = expr2(s);
      if (res3.isErr()) {
        return Result.err(res3.getErr());
      }
      Pair<String, Expression> t3 = res3.getOk();

      s = t3._1;
      Expression e2 = t3._2;
      Expression.Op op = t2._2;
      e = new Expression.Binary(op, e, e2);
    }

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles comparison operators (`==`, `>`, `>=`, `<`, `<=`).
  /// Those operators are _not_ associative and require explicit grouping
  /// with parentheses.
  public static Result<Pair<String, Expression>, Error> expr2(String s) {
    var res1 = expr3(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;

    s = space(s);

    var res2 = binaryOp2(s);
    if (res2.isErr()) {
      return Result.ok(t1);
    }
    Pair<String, Expression.Op> t2 = res2.getOk();
    s = t2._1;

    s = space(s);

    var res3 = expr3(s);
    if (res3.isErr()) {
      return Result.err(res3.getErr());
    }
    Pair<String, Expression> t3 = res3.getOk();

    s = t3._1;
    Expression e2 = t3._2;
    Expression.Op op = t2._2;
    Expression e = t1._2;
    e = new Expression.Binary(op, e, e2);

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles `|`.
  /// It is left associative, so multiple expressions can be combined:
  /// `a | b | c <=> (a | b) | c`
  public static Result<Pair<String, Expression>, Error> expr3(String s) {
    var res1 = expr4(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      var res2 = binaryOp3(s);
      if (res2.isErr()) {
        break;
      }
      Pair<String, Expression.Op> t2 = res2.getOk();
      s = t2._1;

      s = space(s);

      var res3 = expr4(s);
      if (res3.isErr()) {
        return Result.err(res3.getErr());
      }
      Pair<String, Expression> t3 = res3.getOk();

      s = t3._1;
      Expression e2 = t3._2;

      Expression.Op op = t2._2;
      e = new Expression.Binary(op, e, e2);
    }

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles `^`.
  /// It is left associative, so multiple expressions can be combined:
  /// `a ^ b ^ c <=> (a ^ b) ^ c`
  public static Result<Pair<String, Expression>, Error> expr4(String s) {
    var res1 = expr5(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      var res2 = binaryOp4(s);
      if (res2.isErr()) {
        break;
      }
      Pair<String, Expression.Op> t2 = res2.getOk();
      s = t2._1;

      s = space(s);

      var res3 = expr5(s);
      if (res3.isErr()) {
        return Result.err(res3.getErr());
      }
      Pair<String, Expression> t3 = res3.getOk();

      s = t3._1;
      Expression e2 = t3._2;

      Expression.Op op = t2._2;
      e = new Expression.Binary(op, e, e2);
    }

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles `&`.
  /// It is left associative, so multiple expressions can be combined:
  /// `a & b & c <=> (a & b) & c`
  public static Result<Pair<String, Expression>, Error> expr5(String s) {
    var res1 = expr6(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      var res2 = binaryOp5(s);
      if (res2.isErr()) {
        break;
      }
      Pair<String, Expression.Op> t2 = res2.getOk();
      s = t2._1;

      s = space(s);

      var res3 = expr6(s);
      if (res3.isErr()) {
        return Result.err(res3.getErr());
      }
      Pair<String, Expression> t3 = res3.getOk();

      s = t3._1;
      Expression e2 = t3._2;

      Expression.Op op = t2._2;
      e = new Expression.Binary(op, e, e2);
    }

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles `+` and `-`.
  /// They are left associative, so multiple expressions can be combined:
  /// `a + b - c <=> (a + b) - c`
  public static Result<Pair<String, Expression>, Error> expr6(String s) {
    var res1 = expr7(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      var res2 = binaryOp6(s);
      if (res2.isErr()) {
        break;
      }
      Pair<String, Expression.Op> t2 = res2.getOk();
      s = t2._1;

      s = space(s);

      var res3 = expr7(s);
      if (res3.isErr()) {
        return Result.err(res3.getErr());
      }
      Pair<String, Expression> t3 = res3.getOk();

      s = t3._1;
      Expression e2 = t3._2;

      Expression.Op op = t2._2;
      e = new Expression.Binary(op, e, e2);
    }

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles `*` and `/`.
  /// They are left associative, so multiple expressions can be combined:
  /// `a * b / c <=> (a * b) / c`
  public static Result<Pair<String, Expression>, Error> expr7(String s) {
    var res1 = expr8(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      var res2 = binaryOp7(s);
      if (res2.isErr()) {
        break;
      }
      Pair<String, Expression.Op> t2 = res2.getOk();
      s = t2._1;

      s = space(s);

      var res3 = expr8(s);
      if (res3.isErr()) {
        return Result.err(res3.getErr());
      }
      Pair<String, Expression> t3 = res3.getOk();

      s = t3._1;
      Expression e2 = t3._2;

      Expression.Op op = t2._2;
      e = new Expression.Binary(op, e, e2);
    }

    return Result.ok(new Pair<>(s, e));
  }

  /// This level handles `!` (prefix negation)
  public static Result<Pair<String, Expression>, Error> expr8(String s) {

    s = space(s);

    if (s.startsWith("!")) {
      s = space(s.substring(1));

      var res = expr9(s);
      if (res.isErr()) {
        return Result.err(res.getErr());
      }

      Pair<String, Expression> t = res.getOk();
      return Result.ok(new Pair<>(t._1, new Expression.Unary(Expression.Op.Negate, t._2)));
    } else {
      return expr9(s);
    }
  }

  /// This level handles methods. Methods can take either zero or one
  /// argument in addition to the expression they are called on.
  /// The name of the method decides its arity.
  public static Result<Pair<String, Expression>, Error> expr9(String s) {
    var res1 = exprTerm(s);
    if (res1.isErr()) {
      return Result.err(res1.getErr());
    }
    Pair<String, Expression> t1 = res1.getOk();

    s = t1._1;
    Expression e = t1._2;

    while (true) {
      s = space(s);
      if (s.isEmpty()) {
        break;
      }

      if (!s.startsWith(".")) {
        return Result.ok(new Pair<>(s, e));
      }

      s = s.substring(1);
      var res2 = binaryOp8(s);
      if (!res2.isErr()) {
        Pair<String, Expression.Op> t2 = res2.getOk();
        s = space(t2._1);

        if (!s.startsWith("(")) {
          return Result.err(new Error(s, "missing ("));
        }

        s = space(s.substring(1));

        var res3 = expr(s);
        if (res3.isErr()) {
          return Result.err(res3.getErr());
        }

        Pair<String, Expression> t3 = res3.getOk();

        s = space(t3._1);
        if (!s.startsWith(")")) {
          return Result.err(new Error(s, "missing )"));
        }
        s = space(s.substring(1));
        Expression e2 = t3._2;

        Expression.Op op = t2._2;
        e = new Expression.Binary(op, e, e2);
      } else {
        if (s.startsWith("length()")) {
          e = new Expression.Unary(Expression.Op.Length, e);
          s = s.substring(9);
        }
      }
    }

    return Result.ok(new Pair<>(s, e));
  }

  public static Result<Pair<String, Expression>, Error> exprTerm(String s) {
    var res1 = unaryParens(s);
    if (res1.isOk()) {
      return res1;
    }

    var res2 = term(s);
    if (res2.isErr()) {
      return Result.err(res2.getErr());
    }
    Pair<String, Term> t2 = res2.getOk();
    Expression e = new Expression.Value(t2._2);

    return Result.ok(new Pair<>(t2._1, e));
  }

  public static Result<Pair<String, Expression>, Error> unary(String s) {
    s = space(s);

    if (s.startsWith("!")) {
      s = space(s.substring(1));

      var res = expr(s);
      if (res.isErr()) {
        return Result.err(res.getErr());
      }

      Pair<String, Expression> t = res.getOk();
      return Result.ok(new Pair<>(t._1, new Expression.Unary(Expression.Op.Negate, t._2)));
    }

    if (s.startsWith("(")) {
      var res = unaryParens(s);
      if (res.isErr()) {
        return Result.err(res.getErr());
      }

      Pair<String, Expression> t = res.getOk();
      return Result.ok(new Pair<>(t._1, t._2));
    }

    Expression e;
    var res = term(s);
    if (res.isOk()) {
      Pair<String, Term> t = res.getOk();
      s = space(t._1);
      e = new Expression.Value(t._2);
    } else {
      var res2 = unaryParens(s);
      if (res2.isErr()) {
        return Result.err(res2.getErr());
      }

      Pair<String, Expression> t = res2.getOk();
      s = space(t._1);
      e = t._2;
    }

    if (s.startsWith(".length()")) {
      s = space(s.substring(9));
      return Result.ok(new Pair<>(s, new Expression.Unary(Expression.Op.Length, e)));
    } else {
      return Result.err(new Error(s, "unexpected token"));
    }
  }

  public static Result<Pair<String, Expression>, Error> unaryParens(String s) {
    if (s.startsWith("(")) {
      s = space(s.substring(1));

      var res = expr(s);
      if (res.isErr()) {
        return Result.err(res.getErr());
      }

      Pair<String, Expression> t = res.getOk();

      s = space(t._1);
      if (!s.startsWith(")")) {
        return Result.err(new Error(s, "missing )"));
      }

      s = space(s.substring(1));
      return Result.ok(new Pair<>(s, new Expression.Unary(Expression.Op.Parens, t._2)));
    } else {
      return Result.err(new Error(s, "missing ("));
    }
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp0(String s) {
    if (s.startsWith("||")) {
      return Result.ok(new Pair<>(s.substring(2), Expression.Op.Or));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp1(String s) {
    if (s.startsWith("&&")) {
      return Result.ok(new Pair<>(s.substring(2), Expression.Op.And));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp2(String s) {
    if (s.startsWith("<=")) {
      return Result.ok(new Pair<>(s.substring(2), Expression.Op.LessOrEqual));
    }
    if (s.startsWith(">=")) {
      return Result.ok(new Pair<>(s.substring(2), Expression.Op.GreaterOrEqual));
    }
    if (s.startsWith("<")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.LessThan));
    }
    if (s.startsWith(">")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.GreaterThan));
    }
    if (s.startsWith("==")) {
      return Result.ok(new Pair<>(s.substring(2), Expression.Op.Equal));
    }
    if (s.startsWith("!=")) {
      return Result.ok(new Pair<>(s.substring(2), Expression.Op.NotEqual));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp3(String s) {
    if (s.startsWith("^")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.BitwiseXor));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp4(String s) {
    if (s.startsWith("|") && !s.startsWith("||")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.BitwiseOr));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp5(String s) {
    if (s.startsWith("&") && !s.startsWith("&&")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.BitwiseAnd));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp6(String s) {

    if (s.startsWith("+")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.Add));
    }
    if (s.startsWith("-")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.Sub));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp7(String s) {
    if (s.startsWith("*")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.Mul));
    }
    if (s.startsWith("/")) {
      return Result.ok(new Pair<>(s.substring(1), Expression.Op.Div));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }

  public static Result<Pair<String, Expression.Op>, Error> binaryOp8(String s) {
    if (s.startsWith("intersection")) {
      return Result.ok(new Pair<>(s.substring(12), Expression.Op.Intersection));
    }
    if (s.startsWith("union")) {
      return Result.ok(new Pair<>(s.substring(5), Expression.Op.Union));
    }
    if (s.startsWith("contains")) {
      return Result.ok(new Pair<>(s.substring(8), Expression.Op.Contains));
    }
    if (s.startsWith("starts_with")) {
      return Result.ok(new Pair<>(s.substring(11), Expression.Op.Prefix));
    }
    if (s.startsWith("ends_with")) {
      return Result.ok(new Pair<>(s.substring(9), Expression.Op.Suffix));
    }
    if (s.startsWith("matches")) {
      return Result.ok(new Pair<>(s.substring(7), Expression.Op.Regex));
    }

    return Result.err(new Error(s, "unrecognized op"));
  }
}
