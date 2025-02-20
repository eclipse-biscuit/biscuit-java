package org.biscuitsec.biscuit.builder.parser;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.datalog.TemporarySymbolTable;
import org.biscuitsec.biscuit.datalog.expressions.Op;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.builder.parser.Error;
import org.biscuitsec.biscuit.token.builder.parser.Parser;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import org.biscuitsec.biscuit.token.builder.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.biscuitsec.biscuit.datalog.Check.Kind.One;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

class ParserTest {

    @Test
    void testName() {
        Either<Error, Tuple2<String, String>> res = Parser.name("operation(read)");
        assertEquals(Either.right(new Tuple2<>("(read)", "operation")), res);
    }

    @Test
    void testString() {
        Either<Error, Tuple2<String, Term.Str>> res = Parser.string("\"file1 a hello - 123_\"");
        assertEquals(Either.right(new Tuple2<>("", (Term.Str) Utils.string("file1 a hello - 123_"))), res);
    }

    @Test
    void testInteger() {
        Either<Error, Tuple2<String, Term.Integer>> res = Parser.integer("123");
        assertEquals(Either.right(new Tuple2<>("", (Term.Integer) Utils.integer(123))), res);

        Either<Error, Tuple2<String, Term.Integer>> res2 = Parser.integer("-42");
        assertEquals(Either.right(new Tuple2<>("", (Term.Integer) Utils.integer(-42))), res2);
    }

    @Test
    void testDate() {
        Either<Error, Tuple2<String, Term.Date>> res = Parser.date("2019-12-02T13:49:53Z,");
        assertEquals(Either.right(new Tuple2<>(",", new Term.Date(1575294593))), res);
    }

    @Test
    void testVariable() {
        Either<Error, Tuple2<String, Term.Variable>> res = Parser.variable("$name");
        assertEquals(Either.right(new Tuple2<>("", (Term.Variable) Utils.var("name"))), res);
    }

    @Test
    void testFact() throws org.biscuitsec.biscuit.error.Error.Language {
        Either<Error, Tuple2<String, Fact>> res = Parser.fact("right( \"file1\", \"read\" )");
        assertEquals(Either.right(new Tuple2<>("",
                Utils.fact("right", Arrays.asList(Utils.string("file1"), Utils.s("read"))))),
                res);

        Either<Error, Tuple2<String, Fact>> res2 = Parser.fact("right( $var, \"read\" )");
        assertEquals(Either.left(new Error("$var, \"read\" )", "closing parens not found")),
                res2);

        Either<Error, Tuple2<String, Fact>> res3 = Parser.fact("date(2019-12-02T13:49:53Z)");
        assertEquals(Either.right(new Tuple2<>("",
                        Utils.fact("date", List.of(new Term.Date(1575294593))))),
                res3);

        Either<Error, Tuple2<String, Fact>> res4 = Parser.fact("n1:right( \"file1\", \"read\" )");
        assertEquals(Either.right(new Tuple2<>("",
                        Utils.fact("n1:right", Arrays.asList(Utils.string("file1"), Utils.s("read"))))),
                res4);
    }

    @Test
    void testRule() {
        Either<Error, Tuple2<String, Rule>> res =
                Parser.rule("right($resource, \"read\") <- resource($resource), operation(\"read\")");
        assertEquals(Either.right(new Tuple2<>("",
                        Utils.rule("right",
                                Arrays.asList(Utils.var("resource"), Utils.s("read")),
                                Arrays.asList(
                                        Utils.pred("resource", List.of(Utils.var("resource"))),
                                        Utils.pred("operation", List.of(Utils.s("read"))))
                        ))),
                res);
    }

    @Test
    void testRuleWithExpression() {
            Either<Error, Tuple2<String, Rule>> res =
                Parser.rule("valid_date(\"file1\") <- time($0 ), resource( \"file1\"), $0 <= 2019-12-04T09:46:41Z");
        assertEquals(Either.right(new Tuple2<>("",
                        Utils.constrainedRule("valid_date",
                                List.of(Utils.string("file1")),
                                Arrays.asList(
                                        Utils.pred("time", List.of(Utils.var("0"))),
                                        Utils.pred("resource", List.of(Utils.string("file1")))
                                        ),
                                List.of(
                                        new Expression.Binary(
                                                Expression.Op.LessOrEqual,
                                                new Expression.Value(Utils.var("0")),
                                                new Expression.Value(new Term.Date(1575452801)))
                                )
                        ))),
                res);
    }

    @Test
    void testRuleWithExpressionOrdering() {
        Either<Error, Tuple2<String, Rule>> res =
                Parser.rule("valid_date(\"file1\") <- time($0 ), $0 <= 2019-12-04T09:46:41Z, resource(\"file1\")");
        assertEquals(Either.right(new Tuple2<>("",
                        Utils.constrainedRule("valid_date",
                                List.of(Utils.string("file1")),
                                Arrays.asList(
                                        Utils.pred("time", List.of(Utils.var("0"))),
                                        Utils.pred("resource", List.of(Utils.string("file1")))
                                ),
                                List.of(
                                        new Expression.Binary(
                                                Expression.Op.LessOrEqual,
                                                new Expression.Value(Utils.var("0")),
                                                new Expression.Value(new Term.Date(1575452801)))
                                )
                        ))),
                res);
    }

    @Test
    void expressionIntersectionAndContainsTest() {
        Either<Error, Tuple2<String, Expression>> res =
                Parser.expression("[1, 2, 3].intersection([1, 2]).contains(1)");

        assertEquals(Either.right(new Tuple2<>("",
                new Expression.Binary(
                        Expression.Op.Contains,
                        new Expression.Binary(
                                Expression.Op.Intersection,
                                new Expression.Value(Utils.set(new HashSet<>(Arrays.asList(Utils.integer(1), Utils.integer(2), Utils.integer(3))))),
                                new Expression.Value(Utils.set(new HashSet<>(Arrays.asList(Utils.integer(1), Utils.integer(2)))))
                        ),
                        new Expression.Value(Utils.integer(1))
                ))), res);
    }

    @Test
    void expressionIntersectionAndContainsAndLengthEqualsTest() {
        Either<Error, Tuple2<String, Expression>> res =
                Parser.expression("[1, 2, 3].intersection([1, 2]).length() == 2");

        assertEquals(Either.right(new Tuple2<>("",
                new Expression.Binary(
                        Expression.Op.Equal,
                        new Expression.Unary(
                            Expression.Op.Length,
                            new Expression.Binary(
                                    Expression.Op.Intersection,
                                    new Expression.Value(Utils.set(new HashSet<>(Arrays.asList(Utils.integer(1), Utils.integer(2), Utils.integer(3))))),
                                    new Expression.Value(Utils.set(new HashSet<>(Arrays.asList(Utils.integer(1), Utils.integer(2)))))
                            )
                        ),
                        new Expression.Value(Utils.integer(2))
                ))), res);
    }

    @Test
    void testNegatePrecedence() {
        Either<Error, Tuple2<String, Check>> res =
                Parser.check("check if !false && true");
        assertEquals(Either.right(new Tuple2<>("",
                        Utils.check(
                        Utils.constrainedRule("query",
                                new ArrayList<>(),
                                new ArrayList<>(),
                                List.of(
                                        new Expression.Binary(
                                                Expression.Op.And,
                                                new Expression.Unary(
                                                        Expression.Op.Negate,
                                                        new Expression.Value(new Term.Bool(false))
                                                ),
                                                new Expression.Value(new Term.Bool(true))
                                        )
                                )
                        )))),
                res);
    }

    @Test
    void ruleWithFreeExpressionVariables() {
        Either<Error, Tuple2<String, Rule>> res =
                Parser.rule("right($0) <- resource($0), operation(\"read\"), $test");
        assertEquals(
                Either.left(
                        new Error(" resource($0), operation(\"read\"), $test",
                                "rule head or expressions contains variables that are not used in predicates of the rule's body: [test]")
                ),
                res);
    }

    @Test
    void testRuleWithScope() {
        Either<Error, Tuple2<String, Rule>> res =
                Parser.rule("valid_date(\"file1\") <- resource(\"file1\")  trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db, authority ");
        assertEquals(Either.right(new Tuple2<>("",
                        new Rule(
                                new Predicate(
                                        "valid_date",
                                        List.of(Utils.string("file1")
                                        )),
                                Arrays.asList(
                                        Utils.pred("resource", List.of(Utils.string("file1")))
                                ),
                                new ArrayList<>(),
                                Arrays.asList(
                                        Scope.publicKey(new PublicKey(Schema.PublicKey.Algorithm.Ed25519, "6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")),
                                        Scope.authority()
                                )
                        ))),
                res);
    }

    @Test
    void testCheck() {
        Either<Error, Tuple2<String, Check>> res =
                Parser.check("check if resource($0), operation(\"read\") or admin()");
        assertEquals(Either.right(new Tuple2<>("", new Check(
                One,
                Arrays.asList(
                    Utils.rule("query",
                            new ArrayList<>(),
                            Arrays.asList(
                                    Utils.pred("resource", List.of(Utils.var("0"))),
                                    Utils.pred("operation", List.of(Utils.s("read")))
                            )
                    ),
                    Utils.rule("query",
                            new ArrayList<>(),
                            List.of(
                                    Utils.pred("admin", List.of())
                            )
                    )
                    )))),
                res);
    }

    @Test
    void testExpression() {
        Either<Error, Tuple2<String, Expression>> res =
                Parser.expression(" -1 ");

        assertEquals(new Tuple2<String, Expression>("",
                new Expression.Value(Utils.integer(-1))),
                res.get());

        Either<Error, Tuple2<String, Expression>> res2 =
                Parser.expression(" $0 <= 2019-12-04T09:46:41+00:00");

        assertEquals(new Tuple2<String, Expression>("",
                        new Expression.Binary(
                                Expression.Op.LessOrEqual,
                                new Expression.Value(Utils.var("0")),
                                new Expression.Value(new Term.Date(1575452801)))),
                res2.get());

        Either<Error, Tuple2<String, Expression>> res3 =
                Parser.expression(" 1 < $test + 2 ");

        assertEquals(Either.right(new Tuple2<String, Expression>("",
                        new Expression.Binary(
                                Expression.Op.LessThan,
                                new Expression.Value(Utils.integer(1)),
                                new Expression.Binary(
                                        Expression.Op.Add,
                                        new Expression.Value(Utils.var("test")),
                                        new Expression.Value(Utils.integer(2))
                                )
                        )
                )),
                res3);

        SymbolTable s3 = new SymbolTable();
        long test = s3.insert("test");
        Assertions.assertEquals(
                Arrays.asList(
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(1)),
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Variable(test)),
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(2)),
                        new Op.Binary(Op.BinaryOp.Add),
                        new Op.Binary(Op.BinaryOp.LessThan)
                ),
                res3.get()._2.convert(s3).getOps()
        );

        Either<Error, Tuple2<String, Expression>> res4 =
                Parser.expression("  2 < $test && $var2.starts_with(\"test\") && true ");

        assertEquals(Either.right(new Tuple2<String, Expression>("",
                        new Expression.Binary(
                                Expression.Op.And,
                                new Expression.Binary(
                                        Expression.Op.And,
                                        new Expression.Binary(
                                                Expression.Op.LessThan,
                                                new Expression.Value(Utils.integer(2)),
                                                new Expression.Value(Utils.var("test"))
                                        ),
                                        new Expression.Binary(
                                                Expression.Op.Prefix,
                                                new Expression.Value(Utils.var("var2")),
                                                new Expression.Value(Utils.string("test"))
                                        )
                                ),
                                new Expression.Value(new Term.Bool(true))
                        )
                )),
                res4);

        Either<Error, Tuple2<String, Expression>> res5 =
                Parser.expression("  [ \"abc\", \"def\" ].contains($operation) ");

        HashSet<Term> s = new HashSet<>();
        s.add(Utils.s("abc"));
        s.add(Utils.s("def"));

        assertEquals(Either.right(new Tuple2<String, Expression>("",
                        new Expression.Binary(
                                Expression.Op.Contains,
                                new Expression.Value(Utils.set(s)),
                                new Expression.Value(Utils.var("operation"))
                        )
                )),
                res5);
    }

    @Test
    void testParens() throws org.biscuitsec.biscuit.error.Error.Execution {
        Either<Error, Tuple2<String, Expression>> res =
                Parser.expression("  1 + 2 * 3  ");

        assertEquals(Either.right(new Tuple2<String, Expression>("",
                        new Expression.Binary(
                                Expression.Op.Add,
                                new Expression.Value(Utils.integer(1)),
                                new Expression.Binary(
                                        Expression.Op.Mul,
                                        new Expression.Value(Utils.integer(2)),
                                        new Expression.Value(Utils.integer(3))
                                )
                        )
                )),
                res);

        Expression e = res.get()._2;
        SymbolTable s = new SymbolTable();

        org.biscuitsec.biscuit.datalog.expressions.Expression ex = e.convert(s);

        assertEquals(
                Arrays.asList(
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(1)),
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(2)),
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(3)),
                        new Op.Binary(Op.BinaryOp.Mul),
                        new Op.Binary(Op.BinaryOp.Add)
                ),
                ex.getOps()
        );

        Map<Long, org.biscuitsec.biscuit.datalog.Term> variables = new HashMap<>();
        org.biscuitsec.biscuit.datalog.Term value = ex.evaluate(variables, new TemporarySymbolTable(s));
        assertEquals(new org.biscuitsec.biscuit.datalog.Term.Integer(7), value);
        assertEquals("1 + 2 * 3", ex.print(s).get());


        Either<Error, Tuple2<String, Expression>> res2 =
                Parser.expression("  (1 + 2) * 3  ");

        assertEquals(Either.right(new Tuple2<String, Expression>("",
                        new Expression.Binary(
                                Expression.Op.Mul,
                                new Expression.Unary(
                                        Expression.Op.Parens,
                                        new Expression.Binary(
                                                Expression.Op.Add,
                                                new Expression.Value(Utils.integer(1)),
                                                new Expression.Value(Utils.integer(2))
                                        ))
                                ,
                                new Expression.Value(Utils.integer(3))
                        )
                )),
                res2);

        Expression e2 = res2.get()._2;
        SymbolTable s2 = new SymbolTable();

        org.biscuitsec.biscuit.datalog.expressions.Expression ex2 = e2.convert(s2);

        assertEquals(
                Arrays.asList(
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(1)),
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(2)),
                        new Op.Binary(Op.BinaryOp.Add),
                        new Op.Unary(Op.UnaryOp.Parens),
                        new Op.Value(new org.biscuitsec.biscuit.datalog.Term.Integer(3)),
                        new Op.Binary(Op.BinaryOp.Mul)
                ),
                ex2.getOps()
        );

        Map<Long, org.biscuitsec.biscuit.datalog.Term> variables2 = new HashMap<>();
        org.biscuitsec.biscuit.datalog.Term value2 = ex2.evaluate(variables2, new TemporarySymbolTable(s2));
        assertEquals(new org.biscuitsec.biscuit.datalog.Term.Integer(9), value2);
        assertEquals("(1 + 2) * 3", ex2.print(s2).get());
    }

    @Test
    void testDatalogSucceeds() throws org.biscuitsec.biscuit.error.Error.Parser {

        String l1 = "fact1(1, 2)";
        String l2 = "fact2(\"2\")";
        String l3 = "rule1(2) <- fact2(\"2\")";
        String l4 = "check if rule1(2)";
        String toParse = String.join(";", Arrays.asList(l1, l2, l3, l4));

        Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1, toParse);
        assertTrue(output.isRight());

        Block validBlock = new Block();
        validBlock.addFact(l1);
        validBlock.addFact(l2);
        validBlock.addRule(l3);
        validBlock.addCheck(l4);

        output.forEach(block ->
                assertEquals(block, validBlock)
        );
    }

    @Test
    void testDatalogSucceedsArrays() throws org.biscuitsec.biscuit.error.Error.Parser {
        SymbolTable symbols = Biscuit.defaultSymbolTable();

        String l1 = "check if [2, 3].union([2])";
        String toParse = String.join(";", List.of(l1));

        Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1, toParse);
        assertTrue(output.isRight());

        Block validBlock = new Block();
        validBlock.addCheck(l1);

        output.forEach(block ->
                assertEquals(block, validBlock)
        );
    }

    @Test
    void testDatalogSucceedsArraysContains() throws org.biscuitsec.biscuit.error.Error.Parser {
        SymbolTable symbols = Biscuit.defaultSymbolTable();

        String l1 = "check if [2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z].contains(2020-12-04T09:46:41Z)";
        String toParse = String.join(";", List.of(l1));

        Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1,  toParse);
        assertTrue(output.isRight());

        Block validBlock = new Block();
        validBlock.addCheck(l1);

        output.forEach(block ->
                assertEquals(block, validBlock)
        );
    }

    @Test
    void testDatalogFailed() {
        SymbolTable symbols = Biscuit.defaultSymbolTable();

        String l1 = "fact(1)";
        String l2 = "check fact(1)"; // typo missing "if"
        String toParse = String.join(";", Arrays.asList(l1, l2));

        Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1, toParse);
        assertTrue(output.isLeft());
    }

    @Test
    void testDatalogRemoveComment() throws org.biscuitsec.biscuit.error.Error.Parser {
        SymbolTable symbols = Biscuit.defaultSymbolTable();

        String l0 = "// test comment";
        String l1 = "fact1(1, 2);";
        String l2 = "fact2(\"2\");";
        String l3 = "rule1(2) <- fact2(\"2\");";
        String l4 = "// another comment";
        String l5 = "/* test multiline";
        String l6 = "comment */ check if rule1(2);";
        String l7 = "  /* another multiline";
        String l8 = "comment */";
        String toParse = String.join("", Arrays.asList(l0, l1, l2, l3, l4, l5, l6, l7, l8));

        Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1, toParse);
        assertTrue(output.isRight());
    }
}
