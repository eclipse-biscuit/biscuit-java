package org.biscuitsec.biscuit.token.builder.parser;

import org.biscuitsec.biscuit.token.builder.Term;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import org.biscuitsec.biscuit.token.builder.Expression;

import static org.biscuitsec.biscuit.token.builder.parser.Parser.space;
import static org.biscuitsec.biscuit.token.builder.parser.Parser.term;

public class ExpressionParser {
    public static Either<Error, Tuple2<String, Expression>> parse(String s) {
        return expr(space(s));
    }

    // Top-lever parser for an expression. Expression parsers are layered in
    // order to support operator precedence (see https://en.wikipedia.org/wiki/Operator-precedence_parser).
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
    public static Either<Error, Tuple2<String, Expression>> expr(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr1(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.length() == 0) {
                break;
            }

            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp0(s);
            if (res2.isLeft()) {
                break;
            }
            Tuple2<String, Expression.Op> t2 = res2.get();
            s = t2._1;
            Expression.Op op = t2._2;

            s = space(s);

            Either<Error, Tuple2<String, Expression>> res3 = expr1(s);
            if (res3.isLeft()) {
                return Either.left(res3.getLeft());
            }
            Tuple2<String, Expression> t3 = res3.get();

            s = t3._1;
            Expression e2 = t3._2;

            e = new Expression.Binary(op, e, e2);
        }

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles `&&`
    /// `&&` is left associative, so multiple `&&` expressions can be combined:
    /// `a && b && c <=> (a && b) && c`
    public static Either<Error, Tuple2<String, Expression>> expr1(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr2(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.length() == 0) {
                break;
            }

            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp1(s);
            if (res2.isLeft()) {
                break;
            }
            Tuple2<String, Expression.Op> t2 = res2.get();
            s = t2._1;
            Expression.Op op = t2._2;

            s = space(s);

            Either<Error, Tuple2<String, Expression>> res3 = expr2(s);
            if (res3.isLeft()) {
                return Either.left(res3.getLeft());
            }
            Tuple2<String, Expression> t3 = res3.get();

            s = t3._1;
            Expression e2 = t3._2;

            e = new Expression.Binary(op, e, e2);
        }

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles comparison operators (`==`, `>`, `>=`, `<`, `<=`).
    /// Those operators are _not_ associative and require explicit grouping
    /// with parentheses.
    public static Either<Error, Tuple2<String, Expression>> expr2(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr3(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        s = space(s);

        Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp2(s);
        if (res2.isLeft()) {
            return Either.right(t1);

        }
        Tuple2<String, Expression.Op> t2 = res2.get();
        s = t2._1;
        Expression.Op op = t2._2;

        s = space(s);

        Either<Error, Tuple2<String, Expression>> res3 = expr3(s);
        if (res3.isLeft()) {
            return Either.left(res3.getLeft());
        }
        Tuple2<String, Expression> t3 = res3.get();

        s = t3._1;
        Expression e2 = t3._2;

        e = new Expression.Binary(op, e, e2);

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles `|`.
    /// It is left associative, so multiple expressions can be combined:
    /// `a | b | c <=> (a | b) | c`
    public static Either<Error, Tuple2<String, Expression>> expr3(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr4(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.length() == 0) {
                break;
            }

            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp3(s);
            if (res2.isLeft()) {
                break;
            }
            Tuple2<String, Expression.Op> t2 = res2.get();
            s = t2._1;
            Expression.Op op = t2._2;

            s = space(s);

            Either<Error, Tuple2<String, Expression>> res3 = expr4(s);
            if (res3.isLeft()) {
                return Either.left(res3.getLeft());
            }
            Tuple2<String, Expression> t3 = res3.get();

            s = t3._1;
            Expression e2 = t3._2;

            e = new Expression.Binary(op, e, e2);
        }

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles `^`.
    /// It is left associative, so multiple expressions can be combined:
    /// `a ^ b ^ c <=> (a ^ b) ^ c`
    public static Either<Error, Tuple2<String, Expression>> expr4(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr5(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.length() == 0) {
                break;
            }

            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp4(s);
            if (res2.isLeft()) {
                break;
            }
            Tuple2<String, Expression.Op> t2 = res2.get();
            s = t2._1;
            Expression.Op op = t2._2;

            s = space(s);

            Either<Error, Tuple2<String, Expression>> res3 = expr5(s);
            if (res3.isLeft()) {
                return Either.left(res3.getLeft());
            }
            Tuple2<String, Expression> t3 = res3.get();

            s = t3._1;
            Expression e2 = t3._2;

            e = new Expression.Binary(op, e, e2);
        }

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles `&`.
    /// It is left associative, so multiple expressions can be combined:
    /// `a & b & c <=> (a & b) & c`
    public static Either<Error, Tuple2<String, Expression>> expr5(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr6(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.length() == 0) {
                break;
            }

            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp5(s);
            if (res2.isLeft()) {
                break;
            }
            Tuple2<String, Expression.Op> t2 = res2.get();
            s = t2._1;
            Expression.Op op = t2._2;

            s = space(s);

            Either<Error, Tuple2<String, Expression>> res3 = expr6(s);
            if (res3.isLeft()) {
                return Either.left(res3.getLeft());
            }
            Tuple2<String, Expression> t3 = res3.get();

            s = t3._1;
            Expression e2 = t3._2;

            e = new Expression.Binary(op, e, e2);
        }

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles `+` and `-`.
    /// They are left associative, so multiple expressions can be combined:
    /// `a + b - c <=> (a + b) - c`
    public static Either<Error, Tuple2<String, Expression>> expr6(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr7(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.length() == 0) {
                break;
            }

            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp6(s);
            if (res2.isLeft()) {
                break;
            }
            Tuple2<String, Expression.Op> t2 = res2.get();
            s = t2._1;
            Expression.Op op = t2._2;

            s = space(s);

            Either<Error, Tuple2<String, Expression>> res3 = expr7(s);
            if (res3.isLeft()) {
                return Either.left(res3.getLeft());
            }
            Tuple2<String, Expression> t3 = res3.get();

            s = t3._1;
            Expression e2 = t3._2;

            e = new Expression.Binary(op, e, e2);
        }

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles `*` and `/`.
    /// They are left associative, so multiple expressions can be combined:
    /// `a * b / c <=> (a * b) / c`
    public static Either<Error, Tuple2<String, Expression>> expr7(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = expr8(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.length() == 0) {
                break;
            }

            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp7(s);
            if (res2.isLeft()) {
                break;
            }
            Tuple2<String, Expression.Op> t2 = res2.get();
            s = t2._1;
            Expression.Op op = t2._2;

            s = space(s);

            Either<Error, Tuple2<String, Expression>> res3 = expr8(s);
            if (res3.isLeft()) {
                return Either.left(res3.getLeft());
            }
            Tuple2<String, Expression> t3 = res3.get();

            s = t3._1;
            Expression e2 = t3._2;

            e = new Expression.Binary(op, e, e2);
        }

        return Either.right(new Tuple2<>(s, e));
    }

    /// This level handles `!` (prefix negation)
    public static Either<Error, Tuple2<String, Expression>> expr8(String s) {

        s = space(s);

        if(s.startsWith("!")) {
            s = space(s.substring(1));

            Either<Error, Tuple2<String, Expression>> res = expr9(s);
            if (res.isLeft()) {
                return Either.left(res.getLeft());
            }

            Tuple2<String, Expression> t = res.get();
            return Either.right(new Tuple2<>(t._1, new Expression.Unary(Expression.Op.Negate, t._2)));
        } else {
            return expr9(s);
        }
    }

    /// This level handles methods. Methods can take either zero or one
    /// argument in addition to the expression they are called on.
    /// The name of the method decides its arity.
    public static Either<Error, Tuple2<String, Expression>> expr9(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = exprTerm(s);
        if (res1.isLeft()) {
            return Either.left(res1.getLeft());
        }
        Tuple2<String, Expression> t1 = res1.get();

        s = t1._1;
        Expression e = t1._2;

        while(true) {
            s = space(s);
            if(s.isEmpty()) {
                break;
            }

            if (!s.startsWith(".")) {
                return Either.right(new Tuple2<>(s, e));
            }

            s = s.substring(1);
            Either<Error, Tuple2<String, Expression.Op>> res2 = binaryOp8(s);
            if (!res2.isLeft()) {
                Tuple2<String, Expression.Op> t2 = res2.get();
                s = space(t2._1);
                Expression.Op op = t2._2;

                if (!s.startsWith("(")) {
                    return Either.left(new Error(s, "missing ("));
                }

                s = space(s.substring(1));

                Either<Error, Tuple2<String, Expression>> res3 = expr(s);
                if (res3.isLeft()) {
                    return Either.left(res3.getLeft());
                }

                Tuple2<String, Expression> t3 = res3.get();

                s = space(t3._1);
                if (!s.startsWith(")")) {
                    return Either.left(new Error(s, "missing )"));
                }
                s = space(s.substring(1));
                Expression e2 = t3._2;

                e = new Expression.Binary(op, e, e2);
            } else {
                if (s.startsWith("length()")) {
                    e = new Expression.Unary(Expression.Op.Length, e);
                    s = s.substring(9);
                }
            }
        }

        return Either.right(new Tuple2<>(s, e));
    }

    public static Either<Error, Tuple2<String, Expression>> exprTerm(String s) {
        Either<Error, Tuple2<String, Expression>> res1 = unaryParens(s);
        if (res1.isRight()) {
            return res1;
        }

        Either<Error, Tuple2<String, Term>> res2 = term(s);
        if (res2.isLeft()) {
            return Either.left(res2.getLeft());
        }
        Tuple2<String, Term> t2 = res2.get();
        Expression e = new Expression.Value(t2._2);

        return Either.right(new Tuple2<>(t2._1, e));
    }

    public static Either<Error, Tuple2<String, Expression>> unary(String s) {
        s = space(s);

        if(s.startsWith("!")) {
            s = space(s.substring(1));

            Either<Error, Tuple2<String, Expression>> res = expr(s);
            if (res.isLeft()) {
                return Either.left(res.getLeft());
            }

            Tuple2<String, Expression> t = res.get();
            return Either.right(new Tuple2<>(t._1, new Expression.Unary(Expression.Op.Negate, t._2)));
        }


        if(s.startsWith("(")) {
            Either<Error, Tuple2<String, Expression>> res = unaryParens(s);
            if (res.isLeft()) {
                return Either.left(res.getLeft());
            }

            Tuple2<String, Expression> t = res.get();
            return Either.right(new Tuple2<>(t._1,  t._2));
        }

        Expression e;
        Either<Error, Tuple2<String, Term>> res = term(s);
        if (res.isRight()) {
            Tuple2<String, Term> t = res.get();
            s = space(t._1);
            e = new Expression.Value(t._2);
        } else {
            Either<Error, Tuple2<String, Expression>> res2 = unaryParens(s);
            if (res2.isLeft()) {
                return Either.left(res2.getLeft());
            }

            Tuple2<String, Expression> t = res2.get();
            s = space(t._1);
            e = t._2;
        }

        if(s.startsWith(".length()")) {
            s = space(s.substring(9));
            return Either.right(new Tuple2<>(s, new Expression.Unary(Expression.Op.Length, e)));
        } else {
            return Either.left(new Error(s, "unexpected token"));
        }
    }

    public static Either<Error, Tuple2<String, Expression>> unaryParens(String s) {
        if(s.startsWith("(")) {
            s = space(s.substring(1));

            Either<Error, Tuple2<String, Expression>> res = expr(s);
            if (res.isLeft()) {
                return Either.left(res.getLeft());
            }

            Tuple2<String, Expression> t = res.get();

            s = space(t._1);
            if(!s.startsWith(")")) {
                return Either.left(new Error(s, "missing )"));
            }

            s = space(s.substring(1));
            return Either.right(new Tuple2<>(s, new Expression.Unary(Expression.Op.Parens, t._2)));
        } else {
            return Either.left(new Error(s, "missing ("));
        }
    }

    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp0(String s) {
        if(s.startsWith("||")) {
            return Either.right(new Tuple2<>(s.substring(2), Expression.Op.Or));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }

    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp1(String s) {
        if(s.startsWith("&&")) {
            return Either.right(new Tuple2<>(s.substring(2), Expression.Op.And));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }

    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp2(String s) {
        if(s.startsWith("<=")) {
            return Either.right(new Tuple2<>(s.substring(2), Expression.Op.LessOrEqual));
        }
        if(s.startsWith(">=")) {
            return Either.right(new Tuple2<>(s.substring(2), Expression.Op.GreaterOrEqual));
        }
        if(s.startsWith("<")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.LessThan));
        }
        if(s.startsWith(">")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.GreaterThan));
        }
        if(s.startsWith("==")) {
            return Either.right(new Tuple2<>(s.substring(2), Expression.Op.Equal));
        }
        if(s.startsWith("!=")) {
            return Either.right(new Tuple2<>(s.substring(2), Expression.Op.NotEqual));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }


    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp3(String s) {
        if(s.startsWith("^")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.BitwiseXor));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }

    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp4(String s) {
        if(s.startsWith("|") && !s.startsWith("||")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.BitwiseOr));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }

    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp5(String s) {
        if(s.startsWith("&") && !s.startsWith("&&")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.BitwiseAnd));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }

    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp6(String s) {

        if(s.startsWith("+")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.Add));
        }
        if(s.startsWith("-")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.Sub));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }


    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp7(String s) {
        if(s.startsWith("*")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.Mul));
        }
        if(s.startsWith("/")) {
            return Either.right(new Tuple2<>(s.substring(1), Expression.Op.Div));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }

    public static Either<Error, Tuple2<String, Expression.Op>> binaryOp8(String s) {
        if(s.startsWith("intersection")) {
            return Either.right(new Tuple2<>(s.substring(12), Expression.Op.Intersection));
        }
        if(s.startsWith("union")) {
            return Either.right(new Tuple2<>(s.substring(5), Expression.Op.Union));
        }
        if(s.startsWith("contains")) {
            return Either.right(new Tuple2<>(s.substring(8), Expression.Op.Contains));
        }
        if(s.startsWith("starts_with")) {
            return Either.right(new Tuple2<>(s.substring(11), Expression.Op.Prefix));
        }
        if(s.startsWith("ends_with")) {
            return Either.right(new Tuple2<>(s.substring(9), Expression.Op.Suffix));
        }
        if(s.startsWith("matches")) {
            return Either.right(new Tuple2<>(s.substring(7), Expression.Op.Regex));
        }

        return Either.left(new Error(s, "unrecognized op"));
    }
}
