/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import org.eclipse.biscuit.datalog.expressions.Expression;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;
import org.junit.jupiter.api.Test;

public class ExpressionTest {

  @Test
  public void testNegate() throws Error.Execution {
    SymbolTable symbolTable = new SymbolTable();
    symbolTable.add("a");
    symbolTable.add("b");
    symbolTable.add("var");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Term.Integer(1),
                    new Term.Variable(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 2),
                    new Op.Binary(Op.BinaryOp.LessThan),
                    new Op.Unary(Op.UnaryOp.Negate))));

    assertEquals("!1 < $var", e.print(symbolTable).get());

    HashMap<Long, Term> variables = new HashMap<>();
    variables.put(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 2L, new Term.Integer(0));

    assertEquals(new Term.Bool(true), e.evaluate(variables, new TemporarySymbolTable(symbolTable)));
  }

  @Test
  public void testAddsStr() throws Error.Execution {
    SymbolTable symbolTable = new SymbolTable();
    symbolTable.add("a");
    symbolTable.add("b");
    symbolTable.add("ab");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET),
                    new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 1),
                    new Op.Binary(Op.BinaryOp.Add))));

    assertEquals("\"a\" + \"b\"", e.print(symbolTable).get());

    assertEquals(
        new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 2),
        e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbolTable)));
  }

  @Test
  public void testContainsStr() throws Error.Execution {
    SymbolTable symbolTable = new SymbolTable();
    symbolTable.add("ab");
    symbolTable.add("b");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET),
                    new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 1),
                    new Op.Binary(Op.BinaryOp.Contains))));

    assertEquals("\"ab\".contains(\"b\")", e.print(symbolTable).get());

    assertEquals(
        new Term.Bool(true), e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbolTable)));
  }

  @Test
  public void testNegativeContainsStr() throws Error.Execution {
    SymbolTable symbolTable = new SymbolTable();
    symbolTable.add("ab");
    symbolTable.add("b");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET),
                    new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 1),
                    new Op.Binary(Op.BinaryOp.Contains),
                    new Op.Unary(Op.UnaryOp.Negate))));

    assertEquals("!\"ab\".contains(\"b\")", e.print(symbolTable).get());

    assertEquals(
        new Term.Bool(false), e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbolTable)));
  }

  @Test
  public void testIntersectionAndContains() throws Error.Execution {
    SymbolTable symbolTable = new SymbolTable();

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Term.Set(
                        new HashSet<>(
                            Arrays.asList(
                                new Term.Integer(1), new Term.Integer(2), new Term.Integer(3)))),
                    new Term.Set(
                        new HashSet<>(Arrays.asList(new Term.Integer(1), new Term.Integer(2)))),
                    new Op.Binary(Op.BinaryOp.Intersection),
                    new Term.Integer(1),
                    new Op.Binary(Op.BinaryOp.Contains))));

    assertEquals("{1, 2, 3}.intersection({1, 2}).contains(1)", e.print(symbolTable).get());

    assertEquals(
        new Term.Bool(true), e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbolTable)));
  }
}
