/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import org.eclipse.biscuit.datalog.expressions.Expression;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;
import org.junit.jupiter.api.Test;

public class WorldTest {

  @Test
  public void testFamily() throws Error {
    final World w = new World();
    final SymbolTable syms = new SymbolTable();
    final Term a = syms.add("A");
    final Term b = syms.add("B");
    final Term c = syms.add("C");
    final Term d = syms.add("D");
    final Term e = syms.add("E");
    final long parent = syms.insert("parent");
    final long grandparent = syms.insert("grandparent");
    final long sibling = syms.insert("siblings");

    w.addFact(new Origin(0), new Fact(new Predicate(parent, List.of(a, b))));
    w.addFact(new Origin(0), new Fact(new Predicate(parent, List.of(b, c))));
    w.addFact(new Origin(0), new Fact(new Predicate(parent, List.of(c, d))));

    final Rule r1 =
        new Rule(
            new Predicate(
                grandparent,
                List.of(
                    new Term.Variable(syms.insert("grandparent")),
                    new Term.Variable(syms.insert("grandchild")))),
            List.of(
                new Predicate(
                    parent,
                    List.of(
                        new Term.Variable(syms.insert("grandparent")),
                        new Term.Variable(syms.insert("parent")))),
                new Predicate(
                    parent,
                    List.of(
                        new Term.Variable(syms.insert("parent")),
                        new Term.Variable(syms.insert("grandchild"))))),
            new ArrayList<>());

    System.out.println("testing r1: " + syms.formatRule(r1));
    FactSet queryRuleResult = w.queryRule(r1, (long) 0, new TrustedOrigins(0), syms);
    System.out.println(
        "grandparents query_rules: ["
            + queryRuleResult.stream().map(syms::formatFact).collect(Collectors.joining(", "))
            + "]");
    System.out.println(
        "current facts: ["
            + w.getFacts().stream().map(syms::formatFact).collect(Collectors.joining(", "))
            + "]");

    final Rule r2 =
        new Rule(
            new Predicate(
                grandparent,
                List.of(
                    new Term.Variable(syms.insert("grandparent")),
                    new Term.Variable(syms.insert("grandchild")))),
            List.of(
                new Predicate(
                    parent,
                    List.of(
                        new Term.Variable(syms.insert("grandparent")),
                        new Term.Variable(syms.insert("parent")))),
                new Predicate(
                    parent,
                    List.of(
                        new Term.Variable(syms.insert("parent")),
                        new Term.Variable(syms.insert("grandchild"))))),
            new ArrayList<>());

    System.out.println("adding r2: " + syms.formatRule(r2));
    w.addRule((long) 0, new TrustedOrigins(0), r2);
    w.run(syms);

    System.out.println("parents:");
    final Rule query1 =
        new Rule(
            new Predicate(
                parent,
                List.of(
                    new Term.Variable(syms.insert("parent")),
                    new Term.Variable(syms.insert("child")))),
            List.of(
                new Predicate(
                    parent,
                    List.of(
                        new Term.Variable(syms.insert("parent")),
                        new Term.Variable(syms.insert("child"))))),
            new ArrayList<>());

    for (Iterator<Fact> it =
            w.queryRule(query1, (long) 0, new TrustedOrigins(0), syms).stream().iterator();
        it.hasNext(); ) {
      Fact fact = it.next();
      System.out.println("\t" + syms.formatFact(fact));
    }
    final Rule query2 =
        new Rule(
            new Predicate(parent, List.of(new Term.Variable(syms.insert("parent")), b)),
            List.of(new Predicate(parent, List.of(new Term.Variable(syms.insert("parent")), b))),
            new ArrayList<>());
    System.out.println(
        "parents of B: ["
            + String.join(
                ", ",
                w.queryRule(query2, (long) 0, new TrustedOrigins(0), syms).stream()
                    .map(syms::formatFact)
                    .collect(Collectors.toSet()))
            + "]");
    final Rule query3 =
        new Rule(
            new Predicate(
                grandparent,
                List.of(
                    new Term.Variable(syms.insert("grandparent")),
                    new Term.Variable(syms.insert("grandchild")))),
            List.of(
                new Predicate(
                    grandparent,
                    List.of(
                        new Term.Variable(syms.insert("grandparent")),
                        new Term.Variable(syms.insert("grandchild"))))),
            new ArrayList<>());
    System.out.println(
        "grandparents: ["
            + String.join(
                ", ",
                w.queryRule(query3, (long) 0, new TrustedOrigins(0), syms).stream()
                    .map(syms::formatFact)
                    .collect(Collectors.toSet()))
            + "]");

    w.addFact(new Origin(0), new Fact(new Predicate(parent, List.of(c, e))));
    w.run(syms);

    final Rule query4 =
        new Rule(
            new Predicate(
                grandparent,
                List.of(
                    new Term.Variable(syms.insert("grandparent")),
                    new Term.Variable(syms.insert("grandchild")))),
            List.of(
                new Predicate(
                    grandparent,
                    List.of(
                        new Term.Variable(syms.insert("grandparent")),
                        new Term.Variable(syms.insert("grandchild"))))),
            new ArrayList<>());
    final FactSet res = w.queryRule(query4, (long) 0, new TrustedOrigins(0), syms);
    System.out.println(
        "grandparents after inserting parent(C, E): ["
            + String.join(", ", res.stream().map(syms::formatFact).collect(Collectors.toSet()))
            + "]");

    final FactSet expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(new Predicate(grandparent, List.of(a, c))),
                    new Fact(new Predicate(grandparent, List.of(b, d))),
                    new Fact(new Predicate(grandparent, List.of(b, e))))));
    assertEquals(expected, res);

    w.addRule(
        (long) 0,
        new TrustedOrigins(0),
        new Rule(
            new Predicate(
                sibling,
                List.of(
                    new Term.Variable(syms.insert("sibling1")),
                    new Term.Variable(syms.insert("sibling2")))),
            List.of(
                new Predicate(
                    parent,
                    List.of(
                        new Term.Variable(syms.insert("parent")),
                        new Term.Variable(syms.insert("sibling1")))),
                new Predicate(
                    parent,
                    List.of(
                        new Term.Variable(syms.insert("parent")),
                        new Term.Variable(syms.insert("sibling2"))))),
            new ArrayList<>()));
    w.run(syms);

    final Rule query5 =
        new Rule(
            new Predicate(
                sibling,
                List.of(
                    new Term.Variable(syms.insert("sibling1")),
                    new Term.Variable(syms.insert("sibling2")))),
            List.of(
                new Predicate(
                    sibling,
                    List.of(
                        new Term.Variable(syms.insert("sibling1")),
                        new Term.Variable(syms.insert("sibling2"))))),
            new ArrayList<>());
    System.out.println(
        "siblings: ["
            + String.join(
                ", ",
                w.queryRule(query5, (long) 0, new TrustedOrigins(0), syms).stream()
                    .map(syms::formatFact)
                    .collect(Collectors.toSet()))
            + "]");
  }

  @Test
  public void testNumbers() throws Error {
    final World w = new World();
    final SymbolTable syms = new SymbolTable();

    final Term abc = syms.add("abc");
    final Term def = syms.add("def");
    final Term ghi = syms.add("ghi");
    final Term jkl = syms.add("jkl");
    final Term mno = syms.add("mno");
    final Term aaa = syms.add("AAA");
    final Term bbb = syms.add("BBB");
    final Term ccc = syms.add("CCC");
    final long t1 = syms.insert("t1");
    final long t2 = syms.insert("t2");
    final long join = syms.insert("join");

    w.addFact(new Origin(0), new Fact(new Predicate(t1, List.of(new Term.Integer(0), abc))));
    w.addFact(new Origin(0), new Fact(new Predicate(t1, List.of(new Term.Integer(1), def))));
    w.addFact(new Origin(0), new Fact(new Predicate(t1, List.of(new Term.Integer(2), ghi))));
    w.addFact(new Origin(0), new Fact(new Predicate(t1, List.of(new Term.Integer(3), jkl))));
    w.addFact(new Origin(0), new Fact(new Predicate(t1, List.of(new Term.Integer(4), mno))));

    w.addFact(
        new Origin(0),
        new Fact(new Predicate(t2, List.of(new Term.Integer(0), aaa, new Term.Integer(0)))));
    w.addFact(
        new Origin(0),
        new Fact(new Predicate(t2, List.of(new Term.Integer(1), bbb, new Term.Integer(0)))));
    w.addFact(
        new Origin(0),
        new Fact(new Predicate(t2, List.of(new Term.Integer(2), ccc, new Term.Integer(1)))));

    FactSet res =
        w.queryRule(
            new Rule(
                new Predicate(
                    join,
                    List.of(
                        new Term.Variable(syms.insert("left")),
                        new Term.Variable(syms.insert("right")))),
                List.of(
                    new Predicate(
                        t1,
                        List.of(
                            new Term.Variable(syms.insert("id")),
                            new Term.Variable(syms.insert("left")))),
                    new Predicate(
                        t2,
                        List.of(
                            new Term.Variable(syms.insert("t2_id")),
                            new Term.Variable(syms.insert("right")),
                            new Term.Variable(syms.insert("id"))))),
                new ArrayList<>()),
            (long) 0,
            new TrustedOrigins(0),
            syms);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    FactSet expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(new Predicate(join, List.of(abc, aaa))),
                    new Fact(new Predicate(join, List.of(abc, bbb))),
                    new Fact(new Predicate(join, List.of(def, ccc))))));
    assertEquals(expected, res);

    res =
        w.queryRule(
            new Rule(
                new Predicate(
                    join,
                    List.of(
                        new Term.Variable(syms.insert("left")),
                        new Term.Variable(syms.insert("right")))),
                List.of(
                    new Predicate(
                        t1,
                        List.of(
                            new Term.Variable(syms.insert("id")),
                            new Term.Variable(syms.insert("left")))),
                    new Predicate(
                        t2,
                        List.of(
                            new Term.Variable(syms.insert("t2_id")),
                            new Term.Variable(syms.insert("right")),
                            new Term.Variable(syms.insert("id"))))),
                List.of(
                    new Expression(
                        new ArrayList<>(
                            List.of(
                                new Term.Variable(syms.insert("id")),
                                new Term.Integer(1),
                                new Op.Binary(Op.BinaryOp.LessThan)))))),
            (long) 0,
            new TrustedOrigins(0),
            syms);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(new Predicate(join, List.of(abc, aaa))),
                    new Fact(new Predicate(join, List.of(abc, bbb))))));
    assertEquals(expected, res);
  }

  private FactSet testSuffix(
      final World w, SymbolTable syms, final long suff, final long route, final String suffix)
      throws Error {
    return w.queryRule(
        new Rule(
            new Predicate(
                suff,
                List.of(
                    new Term.Variable(syms.insert("app_id")),
                    new Term.Variable(syms.insert("domain")))),
            List.of(
                new Predicate(
                    route,
                    List.of(
                        new Term.Variable(syms.insert("route_id")),
                        new Term.Variable(syms.insert("app_id")),
                        new Term.Variable(syms.insert("domain"))))),
            List.of(
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Variable(syms.insert("domain")),
                            syms.add(suffix),
                            new Op.Binary(Op.BinaryOp.Suffix)))))),
        (long) 0,
        new TrustedOrigins(0),
        syms);
  }

  @Test
  public void testStr() throws Error {
    final World w = new World();
    final SymbolTable syms = new SymbolTable();

    final Term app_0 = syms.add("app_0");
    final Term app_1 = syms.add("app_1");
    final Term app_2 = syms.add("app_2");
    final long route = syms.insert("route");
    final long suff = syms.insert("route suffix");

    w.addFact(
        new Origin(0),
        new Fact(
            new Predicate(route, List.of(new Term.Integer(0), app_0, syms.add("example.com")))));
    w.addFact(
        new Origin(0),
        new Fact(new Predicate(route, List.of(new Term.Integer(1), app_1, syms.add("test.com")))));
    w.addFact(
        new Origin(0),
        new Fact(new Predicate(route, List.of(new Term.Integer(2), app_2, syms.add("test.fr")))));
    w.addFact(
        new Origin(0),
        new Fact(
            new Predicate(
                route, List.of(new Term.Integer(3), app_0, syms.add("www.example.com")))));
    w.addFact(
        new Origin(0),
        new Fact(
            new Predicate(route, List.of(new Term.Integer(4), app_1, syms.add("mx.example.com")))));

    FactSet res = testSuffix(w, syms, suff, route, ".fr");
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    FactSet expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(new Fact(new Predicate(suff, List.of(app_2, syms.add("test.fr")))))));
    assertEquals(expected, res);

    res = testSuffix(w, syms, suff, route, "example.com");
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(new Predicate(suff, List.of(app_0, syms.add("example.com")))),
                    new Fact(new Predicate(suff, List.of(app_0, syms.add("www.example.com")))),
                    new Fact(new Predicate(suff, List.of(app_1, syms.add("mx.example.com")))))));
    assertEquals(expected, res);
  }

  @Test
  public void testDate() throws Error {
    final World w = new World();
    final SymbolTable syms = new SymbolTable();

    final Instant t1 = Instant.now();
    System.out.println("t1 = " + t1);
    final Instant t2 = t1.plusSeconds(10);
    System.out.println("t2 = " + t2);
    final Instant t3 = t2.plusSeconds(30);
    System.out.println("t3 = " + t3);

    final long t2_timestamp = t2.getEpochSecond();

    final Term abc = syms.add("abc");
    final Term def = syms.add("def");
    final long x = syms.insert("x");
    final long before = syms.insert("before");
    final long after = syms.insert("after");

    w.addFact(
        new Origin(0),
        new Fact(new Predicate(x, List.of(new Term.Date(t1.getEpochSecond()), abc))));
    w.addFact(
        new Origin(0),
        new Fact(new Predicate(x, List.of(new Term.Date(t3.getEpochSecond()), def))));

    final Rule r1 =
        new Rule(
            new Predicate(
                before,
                List.of(
                    new Term.Variable(syms.insert("date")), new Term.Variable(syms.insert("val")))),
            List.of(
                new Predicate(
                    x,
                    List.of(
                        new Term.Variable(syms.insert("date")),
                        new Term.Variable(syms.insert("val"))))),
            List.of(
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Variable(syms.insert("date")),
                            new Term.Date(t2_timestamp),
                            new Op.Binary(Op.BinaryOp.LessOrEqual)))),
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Variable(syms.insert("date")),
                            new Term.Date(0),
                            new Op.Binary(Op.BinaryOp.GreaterOrEqual))))));

    System.out.println("testing r1: " + syms.formatRule(r1));
    FactSet res = w.queryRule(r1, (long) 0, new TrustedOrigins(0), syms);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    FactSet expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(
                        new Predicate(before, List.of(new Term.Date(t1.getEpochSecond()), abc))))));
    assertEquals(expected, res);

    final Rule r2 =
        new Rule(
            new Predicate(
                after,
                List.of(
                    new Term.Variable(syms.insert("date")), new Term.Variable(syms.insert("val")))),
            List.of(
                new Predicate(
                    x,
                    List.of(
                        new Term.Variable(syms.insert("date")),
                        new Term.Variable(syms.insert("val"))))),
            List.of(
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Variable(syms.insert("date")),
                            new Term.Date(t2_timestamp),
                            new Op.Binary(Op.BinaryOp.GreaterOrEqual)))),
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Variable(syms.insert("date")),
                            new Term.Date(0),
                            new Op.Binary(Op.BinaryOp.GreaterOrEqual))))));

    System.out.println("testing r2: " + syms.formatRule(r2));
    res = w.queryRule(r2, (long) 0, new TrustedOrigins(0), syms);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(
                        new Predicate(after, List.of(new Term.Date(t3.getEpochSecond()), def))))));
    assertEquals(expected, res);
  }

  @Test
  public void testSet() throws Error {
    final World w = new World();
    final SymbolTable syms = new SymbolTable();

    final Term abc = syms.add("abc");
    final Term def = syms.add("def");
    final long x = syms.insert("x");
    final long int_set = syms.insert("int_set");
    final long symbol_set = syms.insert("symbol_set");
    final long string_set = syms.insert("string_set");

    w.addFact(
        new Origin(0),
        new Fact(new Predicate(x, List.of(abc, new Term.Integer(0), syms.add("test")))));
    w.addFact(
        new Origin(0),
        new Fact(new Predicate(x, List.of(def, new Term.Integer(2), syms.add("hello")))));

    final Rule r1 =
        new Rule(
            new Predicate(
                int_set,
                List.of(
                    new Term.Variable(syms.insert("sym")), new Term.Variable(syms.insert("str")))),
            List.of(
                new Predicate(
                    x,
                    List.of(
                        new Term.Variable(syms.insert("sym")),
                        new Term.Variable(syms.insert("int")),
                        new Term.Variable(syms.insert("str"))))),
            List.of(
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Set(
                                new HashSet<>(List.of(new Term.Integer(0L), new Term.Integer(1L)))),
                            new Term.Variable(syms.insert("int")),
                            new Op.Binary(Op.BinaryOp.Contains))))));
    System.out.println("testing r1: " + syms.formatRule(r1));
    FactSet res = w.queryRule(r1, (long) 0, new TrustedOrigins(0), syms);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    FactSet expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(new Fact(new Predicate(int_set, List.of(abc, syms.add("test")))))));
    assertEquals(expected, res);

    final long abcSymId = syms.insert("abc");
    final long ghiSymId = syms.insert("ghi");

    final Rule r2 =
        new Rule(
            new Predicate(
                symbol_set,
                List.of(
                    new Term.Variable(syms.insert("sym")),
                    new Term.Variable(syms.insert("int")),
                    new Term.Variable(syms.insert("str")))),
            List.of(
                new Predicate(
                    x,
                    List.of(
                        new Term.Variable(syms.insert("sym")),
                        new Term.Variable(syms.insert("int")),
                        new Term.Variable(syms.insert("str"))))),
            List.of(
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Set(
                                new HashSet<>(
                                    List.of(new Term.Str(abcSymId), new Term.Str(ghiSymId)))),
                            new Term.Variable(syms.insert("sym")),
                            new Op.Binary(Op.BinaryOp.Contains),
                            new Op.Unary(Op.UnaryOp.Negate))))));

    System.out.println("testing r2: " + syms.formatRule(r2));
    res = w.queryRule(r2, (long) 0, new TrustedOrigins(0), syms);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(
                        new Predicate(
                            symbol_set, List.of(def, new Term.Integer(2), syms.add("hello")))))));
    assertEquals(expected, res);

    final Rule r3 =
        new Rule(
            new Predicate(
                string_set,
                List.of(
                    new Term.Variable(syms.insert("sym")),
                    new Term.Variable(syms.insert("int")),
                    new Term.Variable(syms.insert("str")))),
            List.of(
                new Predicate(
                    x,
                    List.of(
                        new Term.Variable(syms.insert("sym")),
                        new Term.Variable(syms.insert("int")),
                        new Term.Variable(syms.insert("str"))))),
            List.of(
                new Expression(
                    new ArrayList<>(
                        List.of(
                            new Term.Set(new HashSet<>(List.of(syms.add("test"), syms.add("aaa")))),
                            new Term.Variable(syms.insert("str")),
                            new Op.Binary(Op.BinaryOp.Contains))))));
    System.out.println("testing r3: " + syms.formatRule(r3));
    res = w.queryRule(r3, (long) 0, new TrustedOrigins(0), syms);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    expected =
        new FactSet(
            new Origin(0),
            new HashSet<>(
                List.of(
                    new Fact(
                        new Predicate(
                            string_set, List.of(abc, new Term.Integer(0), syms.add("test")))))));
    assertEquals(expected, res);
  }

  @Test
  public void testResource() throws Error {
    final World w = new World();
    final SymbolTable syms = new SymbolTable();

    final Term authority = syms.add("authority");
    final Term ambient = syms.add("ambient");
    final long resource = syms.insert("resource");
    final long operation = syms.insert("operation");
    final long right = syms.insert("right");
    final Term file1 = syms.add("file1");
    final Term file2 = syms.add("file2");
    final Term read = syms.add("read");
    final Term write = syms.add("write");

    w.addFact(new Origin(0), new Fact(new Predicate(right, List.of(file1, read))));
    w.addFact(new Origin(0), new Fact(new Predicate(right, List.of(file2, read))));
    w.addFact(new Origin(0), new Fact(new Predicate(right, List.of(file1, write))));

    final long caveat1 = syms.insert("caveat1");
    // r1: caveat2(#file1) <- resource(#ambient, #file1)
    final Rule r1 =
        new Rule(
            new Predicate(caveat1, List.of(file1)),
            List.of(new Predicate(resource, List.of(file1))),
            new ArrayList<>());

    System.out.println("testing caveat 1(should return nothing): " + syms.formatRule(r1));
    FactSet res = w.queryRule(r1, (long) 0, new TrustedOrigins(0), syms);
    System.out.println(res);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    assertTrue(res.size() == 0);

    final long caveat2 = syms.insert("caveat2");
    final long var0_id = syms.insert("var0");
    final Term var0 = new Term.Variable(var0_id);
    // r2: caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority,
    // 0?, #read)
    final Rule r2 =
        new Rule(
            new Predicate(caveat2, List.of(var0)),
            List.of(
                new Predicate(resource, List.of(var0)),
                new Predicate(operation, List.of(read)),
                new Predicate(right, List.of(var0, read))),
            new ArrayList<>());

    System.out.println("testing caveat 2: " + syms.formatRule(r2));
    res = w.queryRule(r2, (long) 0, new TrustedOrigins(0), syms);
    System.out.println(res);
    for (Iterator<Fact> it = res.stream().iterator(); it.hasNext(); ) {
      Fact f = it.next();
      System.out.println("\t" + syms.formatFact(f));
    }
    assertTrue(res.size() == 0);
  }

  @Test
  public void testAddRuleEqualButDistinctTrustedOriginsDoesNotThrow() {
    final World w = new World();
    final SymbolTable syms = new SymbolTable();

    final long left = syms.insert("left");
    final long straight = syms.insert("straight");
    final long right = syms.insert("right");
    final Term.Variable a = new Term.Variable(syms.insert("a"));
    final Term.Variable b = new Term.Variable(syms.insert("b"));

    final Rule r1 =
        new Rule(
            new Predicate(left, Arrays.asList(a, b)),
            Arrays.asList(new Predicate(right, Arrays.asList(a, b))),
            new ArrayList<>());
    final Rule r2 =
        new Rule(
            new Predicate(straight, Arrays.asList(a, b)),
            Arrays.asList(new Predicate(right, Arrays.asList(a, b))),
            new ArrayList<>());

    System.out.println("adding r1: " + syms.formatRule(r1));
    System.out.println(
        "adding r2 under an equal but distinct TrustedOrigins instance: " + syms.formatRule(r2));

    assertDoesNotThrow(
        () -> {
          w.addRule(1L, TrustedOrigins.defaultOrigins(), r1);
          w.addRule(1L, TrustedOrigins.defaultOrigins(), r2);
        });
    assertEquals(1, w.getRules().getRules().size());
  }
}
