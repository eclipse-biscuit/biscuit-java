/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import static org.eclipse.biscuit.datalog.Check.Kind.ONE;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import org.eclipse.biscuit.error.Error;

public final class Utils {
  private Utils() {}

  public static Fact fact(String name, List<Term> ids) throws Error.Language {
    return new Fact(name, ids);
  }

  public static Predicate pred(String name, List<Term> ids) {
    return new Predicate(name, ids);
  }

  public static Rule rule(String headName, List<Term> headIds, List<Predicate> predicates) {
    return new Rule(pred(headName, headIds), predicates, new ArrayList<>(), new ArrayList<>());
  }

  public static Rule constrainedRule(
      String headName,
      List<Term> headIds,
      List<Predicate> predicates,
      List<Expression> expressions) {
    return new Rule(pred(headName, headIds), predicates, expressions, new ArrayList<>());
  }

  public static Check check(Rule rule) {
    return new Check(ONE, rule);
  }

  public static Term integer(long i) {
    return new Term.Integer(i);
  }

  public static Term string(String s) {
    return new Term.Str(s);
  }

  public static Term str(String str) {
    return new Term.Str(str);
  }

  public static Term date(Date d) {
    return new Term.Date(d.getTime() / 1000);
  }

  public static Term var(String name) {
    return new Term.Variable(name);
  }

  public static Term set(SortedSet<Term> s) {
    return new Term.Set(s);
  }

  public static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

  public static String byteArrayToHexString(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = HEX_ARRAY[v >>> 4];
      hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static byte[] hexStringToByteArray(String hex) {
    hex = hex.toUpperCase();
    int l = hex.length();
    byte[] data = new byte[l / 2];
    for (int i = 0; i < l; i += 2) {
      data[i / 2] =
          (byte)
              ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }

  public static <U> Comparator<List<U>> listComparator(Comparator<U> comparator) {
    return (o1, o2) -> {
      var c = Integer.compare(o1.size(), o2.size());
      if (c == 0) {
        return iteratorComparator(comparator).compare(o1.iterator(), o2.iterator());
      } else {
        return c;
      }
    };
  }

  public static <U> Comparator<Iterator<U>> iteratorComparator(Comparator<U> comparator) {
    return (o1it, o2it) -> {
      var c = 0;
      while (c == 0) {
        if (o1it.hasNext() && o2it.hasNext()) {
          c = comparator.compare(o1it.next(), o2it.next());
        } else if (o1it.hasNext()) {
          c = 1;
        } else if (o2it.hasNext()) {
          c = -1;
        } else {
          return c;
        }
      }
      return c;
    };
  }

  public static <E> TreeSet<E> treeSetWithComparator(
      Collection<? extends E> c, Comparator<? super E> comparator) {
    var tS = new TreeSet<E>(comparator);
    tS.addAll(c);
    return tS;
  }
}
