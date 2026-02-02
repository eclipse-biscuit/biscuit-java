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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.stream.Collectors;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.expressions.Op;

public abstract class Term extends Expression {
  public abstract org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable);

  public static Term convertFrom(org.eclipse.biscuit.datalog.Term id, SymbolTable symbols) {
    return id.toTerm(symbols);
  }

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
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Integer(this.value);
    }

    public org.eclipse.biscuit.datalog.MapKey convertMapKey(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.datalog.Term.Integer(this.value);
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
    public String toString() {
      return "null";
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      return true;
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
    final HashMap<MapKey, Term> value;

    public Map(HashMap<MapKey, Term> value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      HashMap<org.eclipse.biscuit.datalog.MapKey, org.eclipse.biscuit.datalog.Term> s =
          new HashMap<>();

      for (java.util.Map.Entry<MapKey, Term> i : this.value.entrySet()) {
        s.put(i.getKey().convertMapKey(symbolTable), i.getValue().convert(symbolTable));
      }

      return new org.eclipse.biscuit.datalog.Term.Map(s);
    }

    public java.util.Map<MapKey, Term> getValue() {
      return Collections.unmodifiableMap(value);
    }

    @Override
    public String toString() {
      return value.entrySet().stream()
          .map(entry -> entry.getKey() + ": " + entry.getValue())
          .sorted()
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
    final java.util.Set<Term> value;

    public Set(java.util.Set<Term> value) {
      this.value = value;
    }

    @Override
    public org.eclipse.biscuit.datalog.Term convert(SymbolTable symbolTable) {
      HashSet<org.eclipse.biscuit.datalog.Term> s = new HashSet<>();

      for (Term t : this.value) {
        s.add(t.convert(symbolTable));
      }

      return new org.eclipse.biscuit.datalog.Term.Set(s);
    }

    public java.util.Set<Term> getValue() {
      return Collections.unmodifiableSet(value);
    }

    @Override
    public String toString() {
      if (value.size() == 0) {
        return "{,}";
      }
      String s = "{";
      int count = 0;
      for (Term elem : value) {
        s += elem;
        count += 1;
        if (count < value.size()) {
          s += ", ";
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
