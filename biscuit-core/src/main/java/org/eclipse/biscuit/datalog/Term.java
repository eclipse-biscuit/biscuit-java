/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.DeserializationLimit;
import org.eclipse.biscuit.token.builder.Utils;

public abstract class Term extends Op {
  public enum TermType {
    VARIABLE,
    INTEGER,
    STRING,
    DATE,
    BYTES,
    BOOL,
    SET,
    NULL,
    ARRAY,
    MAP
  }

  public enum MapKeyType {
    INTEGER,
    STRING
  }

  public abstract boolean match(Term other);

  public abstract Schema.Term serializeTerm();

  public abstract String typeOf();

  public abstract TermType getTermType();

  public abstract org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable);

  @Override
  public Schema.Op serialize() {
    return Schema.Op.newBuilder().setValue(this.serializeTerm()).build();
  }

  @Override
  public void evaluate(
      Deque<Op> stack,
      java.util.Map<Long, Term> variables,
      TemporarySymbolTable temporarySymbolTable,
      StepBudget steps)
      throws Error.Execution {
    if (this instanceof Term.Variable) {
      Term.Variable var = (Term.Variable) this;
      Term valueVar = variables.get(var.value());
      if (valueVar != null) {
        stack.push(valueVar);
      } else {
        throw new Error.Execution("cannot find a variable for index " + this);
      }
    } else {
      stack.push(this);
    }
  }

  @Override
  public String print(Deque<String> stack, SymbolTable symbols) {
    String s = symbols.formatTerm(this);
    stack.push(s);
    return s;
  }

  public static Result<Term, Error.FormatError> deserializeEnum(
      Schema.Term term, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
    var allowedTypes = limits.getAllowedTermTypes();
    // a variable is not a value, so it has no type
    var type = termType(term.getContentCase());
    if (allowedTypes != null && type != null && !allowedTypes.contains(type)) {
      return Result.err(
          new Error.FormatError.DeserializationLimitError(
              Error.FormatError.DeserializationLimitError.Reason.TERM_TYPE_NOT_ALLOWED));
    }

    switch (term.getContentCase()) {
      case DATE:
        return Date.deserialize(term);
      case INTEGER:
        return Integer.deserialize(term);
      case STRING:
        var stringError = limits.checkString(symbols, term.getString());
        if (stringError != null) {
          return Result.err(stringError);
        }
        return Str.deserialize(term);
      case BYTES:
        if (term.getBytes().size() > limits.getMaxBytesLength()) {
          return Result.err(
              new Error.FormatError.DeserializationLimitError(
                  Error.FormatError.DeserializationLimitError.Reason.BYTES_TOO_LONG));
        }
        return Bytes.deserialize(term);
      case VARIABLE:
        var nameError =
            limits.checkName(symbols, java.lang.Integer.toUnsignedLong(term.getVariable()));
        if (nameError != null) {
          return Result.err(nameError);
        }
        return Variable.deserialize(term);
      case BOOL:
        return Bool.deserialize(term);
      case SET:
        return Set.deserialize(term, limits, symbols);
      case NULL:
        return Null.deserialize(term);
      case ARRAY:
        return Array.deserialize(term, limits, symbols);
      case MAP:
        return Map.deserialize(term, limits, symbols);
      default:
        return Result.err(
            new Error.FormatError.DeserializationError(
                "invalid Term kind: " + term.getContentCase()));
    }
  }

  /**
   * Total order on terms: first by {@link TermType} (in declaration order), then by value. Strings
   * are compared by symbol index, as in {@link MapKey#comparator}.
   */
  public static Comparator<Term> comparator =
      new Comparator<Term>() {
        @Override
        public int compare(Term o1, Term o2) {
          int c = o1.getTermType().compareTo(o2.getTermType());
          if (c != 0) {
            return c;
          }
          switch (o1.getTermType()) {
            case VARIABLE:
              return Long.compare(((Variable) o1).value(), ((Variable) o2).value());
            case INTEGER:
              return Long.compare(((Integer) o1).value(), ((Integer) o2).value());
            case STRING:
              return Long.compare(((Str) o1).value(), ((Str) o2).value());
            case DATE:
              return Long.compare(((Date) o1).value(), ((Date) o2).value());
            case BYTES:
              return Arrays.compareUnsigned(((Bytes) o1).value(), ((Bytes) o2).value());
            case BOOL:
              return Boolean.compare(((Bool) o1).value(), ((Bool) o2).value());
            case NULL:
              return 0;
            case SET:
              return Utils.iteratorComparator(Term.comparator)
                  .compare(((Set) o1).value().iterator(), ((Set) o2).value().iterator());
            case ARRAY:
              return Utils.iteratorComparator(Term.comparator)
                  .compare(((Array) o1).value().iterator(), ((Array) o2).value().iterator());
            case MAP:
              return Utils.iteratorComparator(MAP_ENTRY_COMPARATOR)
                  .compare(
                      ((Map) o1).value().entrySet().iterator(),
                      ((Map) o2).value().entrySet().iterator());
            default:
              throw new IllegalStateException("unhandled term type " + o1.getTermType());
          }
        }
      };

  private static final Comparator<java.util.Map.Entry<MapKey, Term>> MAP_ENTRY_COMPARATOR =
      new Comparator<java.util.Map.Entry<MapKey, Term>>() {
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

  private static TermType termType(Schema.Term.ContentCase content) {
    switch (content) {
      case INTEGER:
        return TermType.INTEGER;
      case STRING:
        return TermType.STRING;
      case DATE:
        return TermType.DATE;
      case BYTES:
        return TermType.BYTES;
      case BOOL:
        return TermType.BOOL;
      case SET:
        return TermType.SET;
      case NULL:
        return TermType.NULL;
      case ARRAY:
        return TermType.ARRAY;
      case MAP:
        return TermType.MAP;
      case VARIABLE:
      case CONTENT_NOT_SET:
        // not values, so they have no type
        return null;
      default:
        throw new IllegalStateException("unhandled term kind " + content);
    }
  }

  public static final class Null extends Term {
    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      } else {
        return this.equals(other);
      }
    }

    public Null() {}

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

    @Override
    public String toString() {
      return "null";
    }

    public Schema.Term serializeTerm() {
      return Schema.Term.newBuilder().setNull(Schema.Empty.newBuilder().build()).build();
    }

    public String typeOf() {
      return "null";
    }

    @Override
    public TermType getTermType() {
      return TermType.NULL;
    }

    public static Result<Term, Error.FormatError> deserialize(Schema.Term term) {
      if (!term.hasNull()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected null"));
      } else {
        return Result.ok(new Null());
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Null();
    }
  }

  public static final class Date extends Term {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      } else {
        return this.equals(other);
      }
    }

    public Date(final long value) {
      this.value = value;
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

    @Override
    public String toString() {
      return "@" + this.value;
    }

    public Schema.Term serializeTerm() {
      return Schema.Term.newBuilder().setDate(this.value).build();
    }

    public String typeOf() {
      return "date";
    }

    @Override
    public TermType getTermType() {
      return TermType.DATE;
    }

    public static Result<Term, Error.FormatError> deserialize(Schema.Term term) {
      if (!term.hasDate()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected date"));
      } else {
        return Result.ok(new Date(term.getDate()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Date(this.value);
    }
  }

  public static final class Integer extends MapKey {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Integer) {
        return this.value == ((Integer) other).value;
      }
      return false;
    }

    public Integer(final long value) {
      this.value = value;
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

    @Override
    public String toString() {
      return String.valueOf(this.value);
    }

    public Schema.Term serializeTerm() {
      return Schema.Term.newBuilder().setInteger(this.value).build();
    }

    public String typeOf() {
      return "integer";
    }

    @Override
    public TermType getTermType() {
      return TermType.INTEGER;
    }

    @Override
    public MapKeyType getMapKeyType() {
      return MapKeyType.INTEGER;
    }

    public Schema.MapKey serializeMapKey() {
      return Schema.MapKey.newBuilder().setInteger(this.value).build();
    }

    public static Result<Term, Error.FormatError> deserialize(Schema.Term term) {
      if (!term.hasInteger()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected integer"));
      } else {
        return Result.ok(new Integer(term.getInteger()));
      }
    }

    public static Result<MapKey, Error.FormatError> deserializeMapKey(Schema.MapKey term) {
      if (!term.hasInteger()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected integer"));
      } else {
        return Result.ok(new Integer(term.getInteger()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Integer(this.value);
    }

    public org.eclipse.biscuit.token.builder.MapKey toMapKey(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Integer(this.value);
    }
  }

  public static final class Bytes extends Term {
    private final byte[] value;

    public byte[] value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      } else {
        return this.equals(other);
      }
    }

    public Bytes(final byte[] value) {
      this.value = value;
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

    @Override
    public String toString() {
      return this.value.toString();
    }

    public Schema.Term serializeTerm() {
      return Schema.Term.newBuilder().setBytes(ByteString.copyFrom(this.value)).build();
    }

    public String typeOf() {
      return "bytes";
    }

    @Override
    public TermType getTermType() {
      return TermType.BYTES;
    }

    public static Result<Term, Error.FormatError> deserialize(Schema.Term term) {
      if (!term.hasBytes()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected byte array"));
      } else {
        return Result.ok(new Bytes(term.getBytes().toByteArray()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Bytes(this.value);
    }
  }

  public static final class Str extends MapKey {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Str) {
        return this.value == ((Str) other).value;
      }
      return false;
    }

    public Str(final long value) {
      this.value = value;
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

      return value == s.value;
    }

    @Override
    public int hashCode() {
      return Long.hashCode(value);
    }

    public Schema.Term serializeTerm() {
      return Schema.Term.newBuilder().setString(this.value).build();
    }

    public String typeOf() {
      return "string";
    }

    @Override
    public TermType getTermType() {
      return TermType.STRING;
    }

    @Override
    public MapKeyType getMapKeyType() {
      return MapKeyType.STRING;
    }

    public Schema.MapKey serializeMapKey() {
      return Schema.MapKey.newBuilder().setString(this.value).build();
    }

    public static Result<Term, Error.FormatError> deserialize(Schema.Term term) {
      if (!term.hasString()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected string"));
      } else {
        return Result.ok(new Str(term.getString()));
      }
    }

    public static Result<MapKey, Error.FormatError> deserializeMapKey(Schema.MapKey term) {
      if (!term.hasString()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected string"));
      } else {
        return Result.ok(new Str(term.getString()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Str(
          symbolTable.formatSymbol((int) this.value));
    }

    public org.eclipse.biscuit.token.builder.MapKey toMapKey(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Str(
          symbolTable.formatSymbol((int) this.value));
    }
  }

  public static final class Variable extends Term {
    private final long value;

    public long value() {
      return this.value;
    }

    public boolean match(final Term other) {
      return true;
    }

    public Variable(final long value) {
      this.value = value;
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

      return value == variable.value;
    }

    @Override
    public int hashCode() {
      return Long.hashCode(value);
    }

    @Override
    public String toString() {
      return this.value + "?";
    }

    public Schema.Term serializeTerm() {
      return Schema.Term.newBuilder().setVariable((int) this.value).build();
    }

    public String typeOf() {
      throw new InternalError();
    }

    @Override
    public TermType getTermType() {
      return TermType.VARIABLE;
    }

    public static Result<Term, Error.FormatError> deserialize(Schema.Term term) {
      if (!term.hasVariable()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected variable"));
      } else {
        return Result.ok(new Variable(term.getVariable()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Variable(
          symbolTable.formatSymbol((int) this.value));
    }
  }

  public static final class Bool extends Term {
    private final boolean value;

    public boolean value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Bool) {
        return this.value == ((Bool) other).value;
      }
      return false;
    }

    public Bool(final boolean value) {
      this.value = value;
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
      return (value ? 1 : 0);
    }

    @Override
    public String toString() {
      return String.valueOf(this.value);
    }

    public Schema.Term serializeTerm() {
      return Schema.Term.newBuilder().setBool(this.value).build();
    }

    public String typeOf() {
      return "bool";
    }

    @Override
    public TermType getTermType() {
      return TermType.BOOL;
    }

    public static Result<Term, Error.FormatError> deserialize(Schema.Term term) {
      if (!term.hasBool()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected boolean"));
      } else {
        return Result.ok(new Bool(term.getBool()));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      return new org.eclipse.biscuit.token.builder.Term.Bool(this.value);
    }
  }

  public static final class Array extends Term {
    private final List<Term> value;

    public List<Term> value() {
      return Collections.unmodifiableList(this.value);
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Array) {
        return this.value.equals(((Array) other).value);
      }
      return false;
    }

    public Array(final List<Term> value) {
      this.value = value;
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

      return value.equals(array.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public Schema.Term serializeTerm() {
      Schema.Array.Builder s = Schema.Array.newBuilder();

      for (Term l : this.value) {
        s.addArray(l.serializeTerm());
      }

      return Schema.Term.newBuilder().setArray(s).build();
    }

    public String typeOf() {
      return "array";
    }

    @Override
    public TermType getTermType() {
      return TermType.ARRAY;
    }

    public static Result<Term, Error.FormatError> deserialize(
        Schema.Term term, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
      if (!term.hasArray()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected array"));
      } else {
        java.util.List<Term> values = new ArrayList<>();
        Schema.Array s = term.getArray();

        if (s.getArrayCount() > limits.getMaxArrayLength()) {
          return Result.err(
              new Error.FormatError.DeserializationLimitError(
                  Error.FormatError.DeserializationLimitError.Reason.ARRAY_TOO_LONG));
        }

        for (Schema.Term l : s.getArrayList()) {
          var res = Term.deserializeEnum(l, limits, symbols);
          if (res.isErr()) {
            return Result.err(res.getErr());
          } else {
            Term value = res.getOk();

            if (value instanceof Variable) {
              return Result.err(
                  new Error.FormatError.DeserializationError("arrays cannot contain variables"));
            }

            values.add(value);
          }
        }

        if (values.isEmpty()) {
          return Result.err(new Error.FormatError.DeserializationError("invalid Array value"));
        } else {
          return Result.ok(new Array(values));
        }
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      ArrayList<org.eclipse.biscuit.token.builder.Term> s = new ArrayList<>();

      for (Term i : this.value) {
        s.add(i.toTerm(symbolTable));
      }

      return new org.eclipse.biscuit.token.builder.Term.Array(s);
    }
  }

  public static final class Map extends Term {
    private final SortedMap<MapKey, Term> value;

    public SortedMap<MapKey, Term> value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Map) {
        return this.value.equals(((Map) other).value);
      }
      return false;
    }

    public Map(final SortedMap<MapKey, Term> value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Map array = (Map) o;

      return value.equals(array.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public Schema.Term serializeTerm() {
      Schema.Map.Builder s = Schema.Map.newBuilder();

      for (java.util.Map.Entry<MapKey, Term> i : this.value.entrySet()) {
        Schema.MapEntry.Builder m = Schema.MapEntry.newBuilder();
        m.setKey(i.getKey().serializeMapKey());
        m.setValue(i.getValue().serializeTerm());
        s.addEntries(m);
      }

      return Schema.Term.newBuilder().setMap(s).build();
    }

    public String typeOf() {
      return "map";
    }

    @Override
    public TermType getTermType() {
      return TermType.MAP;
    }

    public static Result<Term, Error.FormatError> deserialize(
        Schema.Term term, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
      if (!term.hasMap()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected map"));
      }
      java.util.TreeMap<MapKey, Term> values = new TreeMap<>(MapKey.comparator);
      Schema.Map s = term.getMap();

      if (s.getEntriesCount() > limits.getMaxMapLength()) {
        return Result.err(
            new Error.FormatError.DeserializationLimitError(
                Error.FormatError.DeserializationLimitError.Reason.MAP_TOO_LONG));
      }

      for (Schema.MapEntry l : s.getEntriesList()) {
        var resKey = MapKey.deserializeMapKeyEnum(l.getKey(), limits, symbols);
        if (resKey.isErr()) {
          return Result.err(resKey.getErr());
        }
        var resValue = Term.deserializeEnum(l.getValue(), limits, symbols);
        if (resValue.isErr()) {
          return Result.err(resValue.getErr());
        }
        MapKey key = resKey.getOk();
        Term value = resValue.getOk();
        if (value instanceof Variable) {
          return Result.err(
              new Error.FormatError.DeserializationError("maps cannot contain variables"));
        }
        values.put(key, value);
      }

      if (values.isEmpty()) {
        return Result.err(new Error.FormatError.DeserializationError("invalid map value"));
      } else {
        return Result.ok(new Map(values));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      TreeMap<org.eclipse.biscuit.token.builder.MapKey, org.eclipse.biscuit.token.builder.Term> s =
          new TreeMap<>(org.eclipse.biscuit.token.builder.MapKey.comparator);

      for (java.util.Map.Entry<MapKey, Term> i : this.value.entrySet()) {
        s.put(i.getKey().toMapKey(symbolTable), i.getValue().toTerm(symbolTable));
      }

      return new org.eclipse.biscuit.token.builder.Term.Map(s);
    }
  }

  public static final class Set extends Term {
    private final SortedSet<Term> value;

    public SortedSet<Term> value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Set) {
        return this.value.equals(((Set) other).value);
      }
      return false;
    }

    public Set(final SortedSet<Term> value) {
      this.value = value;
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

      return value.equals(set.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
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

    public Schema.Term serializeTerm() {
      Schema.TermSet.Builder s = Schema.TermSet.newBuilder();

      for (Term l : this.value) {
        s.addSet(l.serializeTerm());
      }

      return Schema.Term.newBuilder().setSet(s).build();
    }

    public String typeOf() {
      return "set";
    }

    @Override
    public TermType getTermType() {
      return TermType.SET;
    }

    public static Result<Term, Error.FormatError> deserialize(
        Schema.Term term, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
      if (!term.hasSet()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected set"));
      } else {
        java.util.SortedSet<Term> values = new TreeSet<>(Term.comparator);
        Schema.TermSet s = term.getSet();

        if (s.getSetCount() > limits.getMaxSetLength()) {
          return Result.err(
              new Error.FormatError.DeserializationLimitError(
                  Error.FormatError.DeserializationLimitError.Reason.SET_TOO_LONG));
        }

        for (Schema.Term l : s.getSetList()) {
          var res = Term.deserializeEnum(l, limits, symbols);
          if (res.isErr()) {
            return Result.err(res.getErr());
          } else {
            Term value = res.getOk();

            if (value instanceof Variable) {
              return Result.err(
                  new Error.FormatError.DeserializationError("sets cannot contain variables"));
            }

            values.add(value);
          }
        }

        return Result.ok(new Set(values));
      }
    }

    public org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable) {
      SortedSet<org.eclipse.biscuit.token.builder.Term> s =
          new TreeSet<>(org.eclipse.biscuit.token.builder.Term.comparator);

      for (Term i : this.value) {
        s.add(i.toTerm(symbolTable));
      }

      return new org.eclipse.biscuit.token.builder.Term.Set(s);
    }
  }
}
