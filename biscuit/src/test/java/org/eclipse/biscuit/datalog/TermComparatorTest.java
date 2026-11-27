/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import org.eclipse.biscuit.datalog.Term.MapKeyType;
import org.eclipse.biscuit.datalog.Term.TermType;
import org.eclipse.biscuit.token.builder.Utils;
import org.junit.jupiter.api.Test;

public class TermComparatorTest {

  private static org.eclipse.biscuit.datalog.Term.Map datalogMap(MapKey k, Term v) {
    var m = new TreeMap<MapKey, Term>(MapKey.comparator);
    m.put(k, v);
    return new Term.Map(m);
  }

  @Test
  public void datalogTermTypes() {
    assertEquals(TermType.VARIABLE, new Term.Variable(0).getTermType());
    assertEquals(TermType.INTEGER, new Term.Integer(0).getTermType());
    assertEquals(TermType.STRING, new Term.Str(0).getTermType());
    assertEquals(TermType.DATE, new Term.Date(0).getTermType());
    assertEquals(TermType.BYTES, new Term.Bytes(new byte[0]).getTermType());
    assertEquals(TermType.BOOL, new Term.Bool(true).getTermType());
    assertEquals(TermType.NULL, new Term.Null().getTermType());
    assertEquals(
        TermType.SET,
        new Term.Set(Utils.treeSetWithComparator(List.of(), Term.comparator)).getTermType());
    assertEquals(TermType.ARRAY, new Term.Array(List.of()).getTermType());
    assertEquals(TermType.MAP, datalogMap(new Term.Integer(1), new Term.Null()).getTermType());
    assertEquals(MapKeyType.INTEGER, new Term.Integer(0).getMapKeyType());
    assertEquals(MapKeyType.STRING, new Term.Str(0).getMapKeyType());
  }

  @Test
  public void datalogOrdering() {
    // ascending order, each element strictly lower than the next
    List<Term> ordered =
        List.of(
            new Term.Variable(5),
            new Term.Integer(-1),
            new Term.Integer(2),
            new Term.Str(1),
            new Term.Str(3),
            new Term.Date(1),
            new Term.Bytes(new byte[] {1}),
            new Term.Bytes(new byte[] {1, 0}),
            new Term.Bytes(new byte[] {(byte) 0xff}),
            new Term.Bool(false),
            new Term.Bool(true),
            new Term.Set(
                Utils.treeSetWithComparator(List.of(new Term.Integer(1)), Term.comparator)),
            new Term.Set(
                Utils.treeSetWithComparator(
                    List.of(new Term.Integer(1), new Term.Integer(2)), Term.comparator)),
            new Term.Null(),
            new Term.Array(List.of(new Term.Integer(1))),
            new Term.Array(List.of(new Term.Integer(1), new Term.Integer(0))),
            datalogMap(new Term.Integer(1), new Term.Integer(1)),
            datalogMap(new Term.Integer(1), new Term.Integer(2)),
            datalogMap(new Term.Str(0), new Term.Integer(0)));
    for (int i = 0; i < ordered.size(); i++) {
      for (int j = 0; j < ordered.size(); j++) {
        assertEquals(
            Integer.signum(Integer.compare(i, j)),
            Integer.signum(Term.comparator.compare(ordered.get(i), ordered.get(j))),
            ordered.get(i) + " vs " + ordered.get(j));
      }
    }
  }

  @Test
  public void datalogMapKeyOrdering() {
    assertTrue(MapKey.comparator.compare(new Term.Integer(100), new Term.Str(0)) < 0);
    assertTrue(MapKey.comparator.compare(new Term.Str(0), new Term.Integer(100)) > 0);
    assertTrue(MapKey.comparator.compare(new Term.Integer(1), new Term.Integer(2)) < 0);
    assertTrue(MapKey.comparator.compare(new Term.Str(2), new Term.Str(1)) > 0);
    assertEquals(0, MapKey.comparator.compare(new Term.Str(2), new Term.Str(2)));
  }

  @Test
  public void builderTermTypes() {
    assertEquals(
        TermType.VARIABLE, new org.eclipse.biscuit.token.builder.Term.Variable("a").getTermType());
    assertEquals(
        TermType.INTEGER, new org.eclipse.biscuit.token.builder.Term.Integer(1).getTermType());
    assertEquals(
        TermType.STRING, new org.eclipse.biscuit.token.builder.Term.Str("a").getTermType());
    assertEquals(TermType.DATE, new org.eclipse.biscuit.token.builder.Term.Date(1).getTermType());
    assertEquals(
        TermType.BYTES,
        new org.eclipse.biscuit.token.builder.Term.Bytes(new byte[0]).getTermType());
    assertEquals(
        TermType.BOOL, new org.eclipse.biscuit.token.builder.Term.Bool(true).getTermType());
    assertEquals(TermType.NULL, new org.eclipse.biscuit.token.builder.Term.Null().getTermType());
    assertEquals(
        TermType.SET,
        new org.eclipse.biscuit.token.builder.Term.Set(
                new TreeSet<org.eclipse.biscuit.token.builder.Term>(
                    org.eclipse.biscuit.token.builder.Term.comparator))
            .getTermType());
    assertEquals(
        TermType.ARRAY, new org.eclipse.biscuit.token.builder.Term.Array(List.of()).getTermType());
    assertEquals(
        TermType.MAP,
        new org.eclipse.biscuit.token.builder.Term.Map(
                new TreeMap<>(org.eclipse.biscuit.token.builder.MapKey.comparator))
            .getTermType());
  }

  @Test
  public void builderOrderingAndSetDeduplication() {
    var b = org.eclipse.biscuit.token.builder.Term.comparator;
    var i1 = new org.eclipse.biscuit.token.builder.Term.Integer(1);
    var i2 = new org.eclipse.biscuit.token.builder.Term.Integer(2);
    var sa = new org.eclipse.biscuit.token.builder.Term.Str("a");
    var sb = new org.eclipse.biscuit.token.builder.Term.Str("b");
    assertTrue(b.compare(i1, i2) < 0);
    assertTrue(b.compare(i2, sa) < 0);
    assertTrue(b.compare(sa, sb) < 0);
    assertEquals(0, b.compare(sa, new org.eclipse.biscuit.token.builder.Term.Str("a")));

    // sets are compared on their sorted content, whatever their iteration order
    var s1 =
        new org.eclipse.biscuit.token.builder.Term.Set(
            Utils.treeSetWithComparator(
                List.of(i2, i1), org.eclipse.biscuit.token.builder.Term.comparator));
    var s2 =
        new org.eclipse.biscuit.token.builder.Term.Set(
            Utils.treeSetWithComparator(
                List.of(i1, i2), org.eclipse.biscuit.token.builder.Term.comparator));
    assertEquals(0, b.compare(s1, s2));

    // converting a set with distinct elements keeps them all (comparator used to return 0)
    var symbols = new SymbolTable();
    var converted =
        (Term.Set)
            new org.eclipse.biscuit.token.builder.Term.Set(
                    Utils.treeSetWithComparator(
                        List.of(i1, i2), org.eclipse.biscuit.token.builder.Term.comparator))
                .convert(symbols);
    assertEquals(2, converted.value().size());
  }
}
