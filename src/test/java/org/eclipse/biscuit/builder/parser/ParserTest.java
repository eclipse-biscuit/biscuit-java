/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.builder.parser;

import static org.eclipse.biscuit.datalog.Check.Kind.ONE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import biscuit.format.schema.Schema;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.TemporarySymbolTable;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.builder.Block;
import org.eclipse.biscuit.token.builder.Check;
import org.eclipse.biscuit.token.builder.Expression;
import org.eclipse.biscuit.token.builder.Predicate;
import org.eclipse.biscuit.token.builder.Rule;
import org.eclipse.biscuit.token.builder.Scope;
import org.eclipse.biscuit.token.builder.Term;
import org.eclipse.biscuit.token.builder.Utils;
import org.eclipse.biscuit.token.builder.parser.Error;
import org.eclipse.biscuit.token.builder.parser.Parser;
import org.junit.jupiter.api.Test;

class ParserTest {

  @Test
  void testName() {
    var res = Parser.name("operation(read)");
    assertEquals(Result.ok(new Tuple2<>("(read)", "operation")), res);
  }

  @Test
  void testString() {
    var res = Parser.string("\"file1 a hello - 123_\"");
    assertEquals(Result.ok(new Tuple2<>("", (Term.Str) Utils.string("file1 a hello - 123_"))), res);
  }

  @Test
  void testInteger() {
    var res = Parser.integer("123");
    assertEquals(Result.ok(new Tuple2<>("", (Term.Integer) Utils.integer(123))), res);

    var res2 = Parser.integer("-42");
    assertEquals(Result.ok(new Tuple2<>("", (Term.Integer) Utils.integer(-42))), res2);
  }

  @Test
  void testDate() {
    var res = Parser.date("2019-12-02T13:49:53Z,");
    assertEquals(Result.ok(new Tuple2<>(",", new Term.Date(1575294593))), res);
  }

  @Test
  void testVariable() {
    var res = Parser.variable("$name");
    assertEquals(Result.ok(new Tuple2<>("", (Term.Variable) Utils.var("name"))), res);
  }

  @Test
  void testFact() throws org.eclipse.biscuit.error.Error.Language {
    var res = Parser.fact("right( \"file1\", \"read\" )");
    assertEquals(
        Result.ok(
            new Tuple2<>(
                "", Utils.fact("right", Arrays.asList(Utils.string("file1"), Utils.str("read"))))),
        res);

    var res2 = Parser.fact("right( $var, \"read\" )");
    assertEquals(Result.err(new Error("$var, \"read\" )", "closing parens not found")), res2);

    var res3 = Parser.fact("date(2019-12-02T13:49:53Z)");
    assertEquals(
        Result.ok(new Tuple2<>("", Utils.fact("date", List.of(new Term.Date(1575294593))))), res3);

    var res4 = Parser.fact("n1:right( \"file1\", \"read\" )");
    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                Utils.fact("n1:right", Arrays.asList(Utils.string("file1"), Utils.str("read"))))),
        res4);
  }

  @Test
  void testRule() {
    var res = Parser.rule("right($resource, \"read\") <- resource($resource), operation(\"read\")");
    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                Utils.rule(
                    "right",
                    Arrays.asList(Utils.var("resource"), Utils.str("read")),
                    Arrays.asList(
                        Utils.pred("resource", List.of(Utils.var("resource"))),
                        Utils.pred("operation", List.of(Utils.str("read"))))))),
        res);
  }

  @Test
  void testRuleWithExpression() {
    var res =
        Parser.rule(
            "valid_date(\"file1\") <- time($0 ), resource( \"file1\"), $0 <= 2019-12-04T09:46:41Z");
    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                Utils.constrainedRule(
                    "valid_date",
                    List.of(Utils.string("file1")),
                    Arrays.asList(
                        Utils.pred("time", List.of(Utils.var("0"))),
                        Utils.pred("resource", List.of(Utils.string("file1")))),
                    List.of(
                        new Expression.Binary(
                            Expression.Op.LessOrEqual,
                            new Expression.Value(Utils.var("0")),
                            new Expression.Value(new Term.Date(1575452801))))))),
        res);
  }

  @Test
  void testRuleWithExpressionOrdering() {
    var res =
        Parser.rule(
            "valid_date(\"file1\") <- time($0 ), $0 <= 2019-12-04T09:46:41Z, resource(\"file1\")");
    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                Utils.constrainedRule(
                    "valid_date",
                    List.of(Utils.string("file1")),
                    Arrays.asList(
                        Utils.pred("time", List.of(Utils.var("0"))),
                        Utils.pred("resource", List.of(Utils.string("file1")))),
                    List.of(
                        new Expression.Binary(
                            Expression.Op.LessOrEqual,
                            new Expression.Value(Utils.var("0")),
                            new Expression.Value(new Term.Date(1575452801))))))),
        res);
  }

  @Test
  void expressionIntersectionAndContainsTest() {
    var res = Parser.expression("[1, 2, 3].intersection([1, 2]).contains(1)");

    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                new Expression.Binary(
                    Expression.Op.Contains,
                    new Expression.Binary(
                        Expression.Op.Intersection,
                        new Expression.Value(
                            Utils.set(
                                new HashSet<>(
                                    Arrays.asList(
                                        Utils.integer(1), Utils.integer(2), Utils.integer(3))))),
                        new Expression.Value(
                            Utils.set(
                                new HashSet<>(Arrays.asList(Utils.integer(1), Utils.integer(2)))))),
                    new Expression.Value(Utils.integer(1))))),
        res);
  }

  @Test
  void expressionIntersectionAndContainsAndLengthEqualsTest() {
    var res = Parser.expression("[1, 2, 3].intersection([1, 2]).length() == 2");

    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                new Expression.Binary(
                    Expression.Op.Equal,
                    new Expression.Unary(
                        Expression.Op.Length,
                        new Expression.Binary(
                            Expression.Op.Intersection,
                            new Expression.Value(
                                Utils.set(
                                    new HashSet<>(
                                        Arrays.asList(
                                            Utils.integer(1),
                                            Utils.integer(2),
                                            Utils.integer(3))))),
                            new Expression.Value(
                                Utils.set(
                                    new HashSet<>(
                                        Arrays.asList(Utils.integer(1), Utils.integer(2))))))),
                    new Expression.Value(Utils.integer(2))))),
        res);
  }

  @Test
  void testNegatePrecedence() {
    var res = Parser.check("check if !false && true");
    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                Utils.check(
                    Utils.constrainedRule(
                        "query",
                        new ArrayList<>(),
                        new ArrayList<>(),
                        List.of(
                            new Expression.Binary(
                                Expression.Op.And,
                                new Expression.Unary(
                                    Expression.Op.Negate,
                                    new Expression.Value(new Term.Bool(false))),
                                new Expression.Value(new Term.Bool(true)))))))),
        res);
  }

  @Test
  void ruleWithFreeExpressionVariables() {
    var res = Parser.rule("right($0) <- resource($0), operation(\"read\"), $test");
    assertEquals(
        Result.err(
            new Error(
                " resource($0), operation(\"read\"), $test",
                "rule head or expressions contains variables that are not used in predicates of the"
                    + " rule's body: [test]")),
        res);
  }

  @Test
  void testRuleWithScope() throws org.eclipse.biscuit.error.Error.FormatError {
    var res =
        Parser.rule(
            "valid_date(\"file1\") <- resource(\"file1\")  trusting"
                + " ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db,"
                + " authority ");
    Rule refRule =
        new Rule(
            new Predicate("valid_date", List.of(Utils.string("file1"))),
            List.of(Utils.pred("resource", List.of(Utils.string("file1")))),
            new ArrayList<>(),
            Arrays.asList(
                Scope.publicKey(
                    PublicKey.load(
                        Schema.PublicKey.Algorithm.Ed25519,
                        "6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")),
                Scope.authority()));
    assertEquals(Result.ok(new Tuple2<>("", refRule)), res);
  }

  @Test
  void testCheck() {
    var res = Parser.check("check if resource($0), operation(\"read\") or admin()");
    assertEquals(
        Result.ok(
            new Tuple2<>(
                "",
                new Check(
                    ONE,
                    Arrays.asList(
                        Utils.rule(
                            "query",
                            new ArrayList<>(),
                            Arrays.asList(
                                Utils.pred("resource", List.of(Utils.var("0"))),
                                Utils.pred("operation", List.of(Utils.str("read"))))),
                        Utils.rule(
                            "query",
                            new ArrayList<>(),
                            List.of(Utils.pred("admin", List.of()))))))),
        res);
  }

  @Test
  void testExpression() {
    var res = Parser.expression(" -1 ");

    assertEquals(
        new Tuple2<String, Expression>("", new Expression.Value(Utils.integer(-1))), res.getOk());

    var res2 = Parser.expression(" $0 <= 2019-12-04T09:46:41+00:00");

    assertEquals(
        new Tuple2<String, Expression>(
            "",
            new Expression.Binary(
                Expression.Op.LessOrEqual,
                new Expression.Value(Utils.var("0")),
                new Expression.Value(new Term.Date(1575452801)))),
        res2.getOk());

    var res3 = Parser.expression(" 1 < $test + 2 ");

    assertEquals(
        Result.ok(
            new Tuple2<String, Expression>(
                "",
                new Expression.Binary(
                    Expression.Op.LessThan,
                    new Expression.Value(Utils.integer(1)),
                    new Expression.Binary(
                        Expression.Op.Add,
                        new Expression.Value(Utils.var("test")),
                        new Expression.Value(Utils.integer(2)))))),
        res3);

    SymbolTable s3 = new SymbolTable();
    long test = s3.insert("test");
    assertEquals(
        Arrays.asList(
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(1)),
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Variable(test)),
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(2)),
            new Op.Binary(Op.BinaryOp.Add),
            new Op.Binary(Op.BinaryOp.LessThan)),
        res3.getOk()._2.convert(s3).getOps());

    var res4 = Parser.expression("  2 < $test && $var2.starts_with(\"test\") && true ");

    assertEquals(
        Result.ok(
            new Tuple2<String, Expression>(
                "",
                new Expression.Binary(
                    Expression.Op.And,
                    new Expression.Binary(
                        Expression.Op.And,
                        new Expression.Binary(
                            Expression.Op.LessThan,
                            new Expression.Value(Utils.integer(2)),
                            new Expression.Value(Utils.var("test"))),
                        new Expression.Binary(
                            Expression.Op.Prefix,
                            new Expression.Value(Utils.var("var2")),
                            new Expression.Value(Utils.string("test")))),
                    new Expression.Value(new Term.Bool(true))))),
        res4);

    var res5 = Parser.expression("  [ \"abc\", \"def\" ].contains($operation) ");

    HashSet<Term> s = new HashSet<>();
    s.add(Utils.str("abc"));
    s.add(Utils.str("def"));

    assertEquals(
        Result.ok(
            new Tuple2<String, Expression>(
                "",
                new Expression.Binary(
                    Expression.Op.Contains,
                    new Expression.Value(Utils.set(s)),
                    new Expression.Value(Utils.var("operation"))))),
        res5);
  }

  @Test
  void testParens() throws org.eclipse.biscuit.error.Error.Execution {
    var res = Parser.expression("  1 + 2 * 3  ");

    assertEquals(
        Result.ok(
            new Tuple2<String, Expression>(
                "",
                new Expression.Binary(
                    Expression.Op.Add,
                    new Expression.Value(Utils.integer(1)),
                    new Expression.Binary(
                        Expression.Op.Mul,
                        new Expression.Value(Utils.integer(2)),
                        new Expression.Value(Utils.integer(3)))))),
        res);

    Expression e = res.getOk()._2;
    SymbolTable s = new SymbolTable();

    org.eclipse.biscuit.datalog.expressions.Expression ex = e.convert(s);

    assertEquals(
        Arrays.asList(
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(1)),
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(2)),
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(3)),
            new Op.Binary(Op.BinaryOp.Mul),
            new Op.Binary(Op.BinaryOp.Add)),
        ex.getOps());

    Map<Long, org.eclipse.biscuit.datalog.Term> variables = new HashMap<>();
    org.eclipse.biscuit.datalog.Term value = ex.evaluate(variables, new TemporarySymbolTable(s));
    assertEquals(new org.eclipse.biscuit.datalog.Term.Integer(7), value);
    assertEquals("1 + 2 * 3", ex.print(s).get());

    var res2 = Parser.expression("  (1 + 2) * 3  ");

    assertEquals(
        Result.ok(
            new Tuple2<String, Expression>(
                "",
                new Expression.Binary(
                    Expression.Op.Mul,
                    new Expression.Unary(
                        Expression.Op.Parens,
                        new Expression.Binary(
                            Expression.Op.Add,
                            new Expression.Value(Utils.integer(1)),
                            new Expression.Value(Utils.integer(2)))),
                    new Expression.Value(Utils.integer(3))))),
        res2);

    Expression e2 = res2.getOk()._2;
    SymbolTable s2 = new SymbolTable();

    org.eclipse.biscuit.datalog.expressions.Expression ex2 = e2.convert(s2);

    assertEquals(
        Arrays.asList(
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(1)),
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(2)),
            new Op.Binary(Op.BinaryOp.Add),
            new Op.Unary(Op.UnaryOp.Parens),
            new Op.Value(new org.eclipse.biscuit.datalog.Term.Integer(3)),
            new Op.Binary(Op.BinaryOp.Mul)),
        ex2.getOps());

    Map<Long, org.eclipse.biscuit.datalog.Term> variables2 = new HashMap<>();
    org.eclipse.biscuit.datalog.Term value2 =
        ex2.evaluate(variables2, new TemporarySymbolTable(s2));
    assertEquals(new org.eclipse.biscuit.datalog.Term.Integer(9), value2);
    assertEquals("(1 + 2) * 3", ex2.print(s2).get());
  }

  @Test
  void testDatalogSucceeds() throws org.eclipse.biscuit.error.Error.Parser {

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

    output.forEach(block -> assertEquals(block, validBlock));
  }

  @Test
  void testDatalogSucceedsArrays() throws org.eclipse.biscuit.error.Error.Parser {
    String l1 = "check if [2, 3].union([2])";
    String toParse = String.join(";", List.of(l1));

    Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1, toParse);
    assertTrue(output.isRight());

    Block validBlock = new Block();
    validBlock.addCheck(l1);

    output.forEach(block -> assertEquals(block, validBlock));
  }

  @Test
  void testDatalogSucceedsArraysContains() throws org.eclipse.biscuit.error.Error.Parser {
    String l1 =
        "check if [2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z].contains(2020-12-04T09:46:41Z)";
    String toParse = String.join(";", List.of(l1));

    Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1, toParse);
    assertTrue(output.isRight());

    Block validBlock = new Block();
    validBlock.addCheck(l1);

    output.forEach(block -> assertEquals(block, validBlock));
  }

  @Test
  void testDatalogFailed() {
    String l1 = "fact(1)";
    String l2 = "check fact(1)"; // typo missing "if"
    String toParse = String.join(";", Arrays.asList(l1, l2));

    Either<Map<Integer, List<Error>>, Block> output = Parser.datalog(1, toParse);
    assertTrue(output.isLeft());
  }

  @Test
  void testDatalogRemoveComment() {

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
