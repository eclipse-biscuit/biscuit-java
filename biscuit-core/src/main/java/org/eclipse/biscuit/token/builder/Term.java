/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Objects;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.Term.MapKeyType;
import org.eclipse.biscuit.datalog.expressions.Op;

public abstract class Term extends Expression {
  public abstract org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable);

  public abstract org.eclipse.biscuit.datalog.Term.TermType getTermType();

  public static Term convertFrom(org.eclipse.biscuit.datalog.Term id, SymbolTable symbols) {
    return id.toTerm(symbols);
  }

  /**
   * Total order on builder terms: first by {@link org.eclipse.biscuit.datalog.Term.TermType} (in
   * declaration order), then by value. Mirrors {@link org.eclipse.biscuit.datalog.Term#comparator},
   * except that strings are compared by content rather than by symbol index.
   */
  public static final Comparator<Term> comparator =
      new Comparator<>() {
        @Override
        public int compare(Term o1, Term o2) {
          int c = o1.getTermType().compareTo(o2.getTermType());
          if (c != 0) {
            return c;
          }
          switch (o1.getTermType()) {
            case VARIABLE:
              return ((Variable) o1).value.compareTo(((Variable) o2).value);
            case INTEGER:
              return Long.compare(((Integer) o1).value, ((Integer) o2).value);
            case STRING:
              return ((Str) o1).value.compareTo(((Str) o2).value);
            case DATE:
              return Long.compare(((Date) o1).value, ((Date) o2).value);
            case BYTES:
              return Arrays.compareUnsigned(((Bytes) o1).value, ((Bytes) o2).value);
            case BOOL:
              return Boolean.compare(((Bool) o1).value, ((Bool) o2).value);
            case NULL:
              return 0;
            case SET:
              return Utils.iteratorComparator(Term.comparator)
                  .compare(
                      Utils.treeSetWithComparator(((Set) o1).value, Term.comparator).iterator(),
                      Utils.treeSetWithComparator(((Set) o2).value, Term.comparator).iterator());
            case ARRAY:
              return Utils.iteratorComparator(Term.comparator)
                  .compare(((Array) o1).value.iterator(), ((Array) o2).value.iterator());
            case MAP:
              return Utils.iteratorComparator(MAP_ENTRY_COMPARATOR)
                  .compare(
                      ((Map) o1).value.entrySet().iterator(),
                      ((Map) o2).value.entrySet().iterator());
            default:
              throw new IllegalStateException("unhandled term type " + o1.getTermType());
          }
        }
      };

  private static final Comparator<java.util.Map.Entry<MapKey, Term>> MAP_ENTRY_COMPARATOR =
      new Comparator<>() {
        @Override
        public int compare(
            java.util.Map.Entry<MapKey, Term> e1, java.util.Map.Entry<MapKey, Term> e2) {
          int c = MapKey.comparator.compare(e1.getKey(), e2.getKey());
          if (c != 0) {
            return c;
          }
          return Term.comparator.compare(e1.getValue(), e2.getValue());
        }
      };

  public void toOpcodes(SymbolTable symbolTable, java.util.List<Op> ops) {
    ops.add(this.convert(symbolTable));
  }

  public void gatherVariables(java.util.Set<String> variables) {
    if (this instanceof Term.Variable) {
      variables.add(((Term.Variable) this).value);
    }
  }

  public static final class Str extends MapKey {
    final String value;

    public Str(String value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Str(symbolTable.insert(this.value));
    }

    @Override
    public MapKeyType getMapKeyType() {
      return MapKeyType.STRING;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.STRING;
    }

    public org.eclipse.biscuit.datalog.MapKey convertMapKey(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Str(symbolTable.insert(this.value));
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return "\"" + value + "\"";
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      Str s = (Str) o;
      return Objects.equals(value, s.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
    }
  }

  public static final class Variable extends Term {
    final String value;

    public Variable(String value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Variable(symbolTable.insert(this.value));
    }

    public String getValue() {
      return value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.VARIABLE;
    }

    @Override
    public String toString() {
      return "$" + value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Variable variable = (Variable) o;

      return value.equals(variable.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
    }
  }

  public static final class Integer extends MapKey {
    final long value;

    public Integer(long value) {
      this.value = value;
    }

    public long getValue() {
      return value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.INTEGER;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Integer(this.value);
    }

    public org.eclipse.biscuit.datalog.MapKey convertMapKey(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Integer(this.value);
    }

    @Override
    public MapKeyType getMapKeyType() {
      return MapKeyType.INTEGER;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Integer integer = (Integer) o;

      return value == integer.value;
    }

    @Override
    public int hashCode() {
      return Long.hashCode(value);
    }
  }

  public static final class Bytes extends Term {
    final byte[] value;

    public Bytes(byte[] value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Bytes(this.value);
    }

    public byte[] getValue() {
      return Arrays.copyOf(value, value.length);
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.BYTES;
    }

    @Override
    public String toString() {
      return "hex:" + Utils.byteArrayToHexString(value).toLowerCase();
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Bytes bytes = (Bytes) o;

      return Arrays.equals(value, bytes.value);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(value);
    }
  }

  public static final class Null extends Term {
    public Null() {}

    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Null();
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.NULL;
    }

    @Override
    public String toString() {
      return "null";
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public int hashCode() {
      return 0;
    }
  }

  public static final class Date extends Term {
    final long value;

    public Date(long value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Date(this.value);
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.DATE;
    }

    public long getValue() {
      return value;
    }

    @Override
    public String toString() {
      DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ISO_INSTANT;
      return Instant.ofEpochSecond(value)
          .atOffset(ZoneOffset.ofTotalSeconds(0))
          .format(dateTimeFormatter);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Date date = (Date) o;

      return value == date.value;
    }

    @Override
    public int hashCode() {
      return Long.hashCode(value);
    }
  }

  public static final class Bool extends Term {
    final boolean value;

    public Bool(boolean value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Bool(this.value);
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.BOOL;
    }

    public boolean getValue() {
      return value;
    }

    @Override
    public String toString() {
      if (value) {
        return "true";
      } else {
        return "false";
      }
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Bool bool = (Bool) o;

      return value == bool.value;
    }

    @Override
    public int hashCode() {
      return Boolean.hashCode(value);
    }
  }

  public static final class Array extends Term {
    final java.util.List<Term> value;

    public Array(java.util.List<Term> value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Array(
          value.stream().map(t -> t.convert(symbolTable)).collect(Collectors.toList()));
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.ARRAY;
    }

    public java.util.List<Term> getValue() {
      return Collections.unmodifiableList(value);
    }

    @Override
    public String toString() {
      return value.toString();
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Array array = (Array) o;

      return Objects.equals(value, array.value);
    }

    @Override
    public int hashCode() {
      return value != null ? value.hashCode() : 0;
    }
  }

  public static final class Map extends Term {
    final SortedMap<MapKey, Term> value;

    public Map(SortedMap<MapKey, Term> value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      SortedMap<org.eclipse.biscuit.datalog.MapKey, org.eclipse.biscuit.datalog.Term> s =
          new TreeMap<>(org.eclipse.biscuit.datalog.MapKey.comparator);

      for (java.util.Map.Entry<MapKey, Term> i : this.value.entrySet()) {
        s.put(i.getKey().convertMapKey(symbolTable), i.getValue().convert(symbolTable));
      }

      return new org.eclipse.biscuit.datalog.Term.Map(s);
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.MAP;
    }

    public java.util.Map<MapKey, Term> getValue() {
      return Collections.unmodifiableMap(value);
    }

    @Override
    public String toString() {
      return value.entrySet().stream()
          .map(entry -> entry.getKey() + ": " + entry.getValue())
          .collect(Collectors.joining(", ", "{", "}"));
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Map map = (Map) o;

      return Objects.equals(value, map.value);
    }

    @Override
    public int hashCode() {
      return value != null ? value.hashCode() : 0;
    }
  }

  public static final class Set extends Term {
    final java.util.SortedSet<Term> value;

    public Set(java.util.SortedSet<Term> value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      SortedSet<org.eclipse.biscuit.datalog.Term> s =
          new TreeSet<org.eclipse.biscuit.datalog.Term>(
              org.eclipse.biscuit.datalog.Term.comparator);

      for (Term t : this.value) {
        s.add(t.convert(symbolTable));
      }

      return new org.eclipse.biscuit.datalog.Term.Set(s);
    }

    @Override
    public org.eclipse.biscuit.datalog.Term.TermType getTermType() {
      return org.eclipse.biscuit.datalog.Term.TermType.SET;
    }

    public java.util.Set<Term> getValue() {
      return Collections.unmodifiableSet(value);
    }

    @Override
    public String toString() {
      if (value.isEmpty()) {
        return "{,}";
      }
      StringBuilder s = new StringBuilder("{");
      int count = 0;
      for (Term elem : value) {
        s.append(elem);
        count += 1;
        if (count < value.size()) {
          s.append(", ");
        }
      }
      return s + "}";
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Set set = (Set) o;

      return Objects.equals(value, set.value);
    }

    @Override
    public int hashCode() {
      return value != null ? value.hashCode() : 0;
    }
  }
}
