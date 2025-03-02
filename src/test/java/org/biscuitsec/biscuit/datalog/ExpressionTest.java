package org.biscuitsec.biscuit.datalog;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import org.biscuitsec.biscuit.datalog.expressions.Expression;
import org.biscuitsec.biscuit.datalog.expressions.Op;
import org.biscuitsec.biscuit.error.Error;
import org.junit.jupiter.api.Test;

public class ExpressionTest {

  @Test
  public void testNegate() throws Error.Execution {
    SymbolTable symbols = new SymbolTable();
    symbols.add("a");
    symbols.add("b");
    symbols.add("var");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Op.Value(new Term.Integer(1)),
                    new Op.Value(new Term.Variable(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 2)),
                    new Op.Binary(Op.BinaryOp.LessThan),
                    new Op.Unary(Op.UnaryOp.Negate))));

    assertEquals("!1 < $var", e.print(symbols).get());

    HashMap<Long, Term> variables = new HashMap<>();
    variables.put(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 2L, new Term.Integer(0));

    assertEquals(new Term.Bool(true), e.evaluate(variables, new TemporarySymbolTable(symbols)));
  }

  @Test
  public void testAddsStr() throws Error.Execution {
    SymbolTable symbols = new SymbolTable();
    symbols.add("a");
    symbols.add("b");
    symbols.add("ab");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Op.Value(new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET)),
                    new Op.Value(new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 1)),
                    new Op.Binary(Op.BinaryOp.Add))));

    assertEquals("\"a\" + \"b\"", e.print(symbols).get());

    assertEquals(
        new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 2),
        e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbols)));
  }

  @Test
  public void testContainsStr() throws Error.Execution {
    SymbolTable symbols = new SymbolTable();
    symbols.add("ab");
    symbols.add("b");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Op.Value(new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET)),
                    new Op.Value(new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 1)),
                    new Op.Binary(Op.BinaryOp.Contains))));

    assertEquals("\"ab\".contains(\"b\")", e.print(symbols).get());

    assertEquals(
        new Term.Bool(true), e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbols)));
  }

  @Test
  public void testNegativeContainsStr() throws Error.Execution {
    SymbolTable symbols = new SymbolTable();
    symbols.add("ab");
    symbols.add("b");

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Op.Value(new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET)),
                    new Op.Value(new Term.Str(SymbolTable.DEFAULT_SYMBOLS_OFFSET + 1)),
                    new Op.Binary(Op.BinaryOp.Contains),
                    new Op.Unary(Op.UnaryOp.Negate))));

    assertEquals("!\"ab\".contains(\"b\")", e.print(symbols).get());

    assertEquals(
        new Term.Bool(false), e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbols)));
  }

  @Test
  public void testIntersectionAndContains() throws Error.Execution {
    SymbolTable symbols = new SymbolTable();

    Expression e =
        new Expression(
            new ArrayList<Op>(
                Arrays.asList(
                    new Op.Value(
                        new Term.Set(
                            new HashSet<>(
                                Arrays.asList(
                                    new Term.Integer(1),
                                    new Term.Integer(2),
                                    new Term.Integer(3))))),
                    new Op.Value(
                        new Term.Set(
                            new HashSet<>(
                                Arrays.asList(new Term.Integer(1), new Term.Integer(2))))),
                    new Op.Binary(Op.BinaryOp.Intersection),
                    new Op.Value(new Term.Integer(1)),
                    new Op.Binary(Op.BinaryOp.Contains))));

    assertEquals("[1, 2, 3].intersection([1, 2]).contains(1)", e.print(symbols).get());

    assertEquals(
        new Term.Bool(true), e.evaluate(new HashMap<>(), new TemporarySymbolTable(symbols)));
  }
}
