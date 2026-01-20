/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;

public abstract class Term extends Op implements Serializable {

  public abstract boolean match(Term other);

  public abstract Schema.TermV2 serializeTerm();

  public abstract String typeOf();

  public abstract org.eclipse.biscuit.token.builder.Term toTerm(SymbolTable symbolTable);

  @Override
  public Schema.Op serialize() {
    return Schema.Op.newBuilder().setValue(this.serializeTerm()).build();
  }

  @Override
  public void evaluate(
      Deque<Op> stack,
      java.util.Map<Long, Term> variables,
      TemporarySymbolTable temporarySymbolTable)
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

  public static Result<Term, Error.FormatError> deserializeEnumV2(Schema.TermV2 term) {
    if (term.hasDate()) {
      return Date.deserializeV2(term);
    } else if (term.hasInteger()) {
      return Integer.deserializeV2(term);
    } else if (term.hasString()) {
      return Str.deserializeV2(term);
    } else if (term.hasBytes()) {
      return Bytes.deserializeV2(term);
    } else if (term.hasVariable()) {
      return Variable.deserializeV2(term);
    } else if (term.hasBool()) {
      return Bool.deserializeV2(term);
    } else if (term.hasSet()) {
      return Set.deserializeV2(term);
    } else if (term.hasNull()) {
      return Null.deserializeV2(term);
    } else if (term.hasArray()) {
      return Array.deserializeV2(term);
    } else if (term.hasMap()) {
      return Map.deserializeV2(term);
    } else {
      return Result.err(
          new Error.FormatError.DeserializationError("invalid Term kind: term.getKind()"));
    }
  }

  public static final class Null extends Term implements Serializable {
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
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      return true;
    }

    @Override
    public int hashCode() {
      return 0;
    }

    @Override
    public String toString() {
      return "null";
    }

    public Schema.TermV2 serializeTerm() {
      return Schema.TermV2.newBuilder().setNull(Schema.Empty.newBuilder().build()).build();
    }

    public String typeOf() {
      return "null";
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
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

  public static final class Date extends Term implements Serializable {
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
      return (int) (value ^ (value >>> 32));
    }

    @Override
    public String toString() {
      return "@" + this.value;
    }

    public Schema.TermV2 serializeTerm() {
      return Schema.TermV2.newBuilder().setDate(this.value).build();
    }

    public String typeOf() {
      return "date";
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
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

  public static final class Integer extends MapKey implements Serializable {
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
      return (int) (value ^ (value >>> 32));
    }

    @Override
    public String toString() {
      return "" + this.value;
    }

    public Schema.TermV2 serializeTerm() {
      return Schema.TermV2.newBuilder().setInteger(this.value).build();
    }

    public String typeOf() {
      return "integer";
    }

    public Schema.MapKey serializeMapKey() {
      return Schema.MapKey.newBuilder().setInteger(this.value).build();
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
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

  public static final class Bytes extends Term implements Serializable {
    private final byte[] value;

    public byte[] value() {
      return this.value;
    }

    public boolean match(final Term other) {
      if (other instanceof Variable) {
        return true;
      }
      if (other instanceof Bytes) {
        return this.value.equals(((Bytes) other).value);
      }
      return false;
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

    public Schema.TermV2 serializeTerm() {
      return Schema.TermV2.newBuilder().setBytes(ByteString.copyFrom(this.value)).build();
    }

    public String typeOf() {
      return "bytes";
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
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

  public static final class Str extends MapKey implements Serializable {
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
      return (int) (value ^ (value >>> 32));
    }

    public Schema.TermV2 serializeTerm() {
      return Schema.TermV2.newBuilder().setString(this.value).build();
    }

    public String typeOf() {
      return "string";
    }

    public Schema.MapKey serializeMapKey() {
      return Schema.MapKey.newBuilder().setString(this.value).build();
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
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

  public static final class Variable extends Term implements Serializable {
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
      return (int) (value ^ (value >>> 32));
    }

    @Override
    public String toString() {
      return this.value + "?";
    }

    public Schema.TermV2 serializeTerm() {
      return Schema.TermV2.newBuilder().setVariable((int) this.value).build();
    }

    public String typeOf() {
      throw new InternalError();
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
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

  public static final class Bool extends Term implements Serializable {
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
      return "" + this.value;
    }

    public Schema.TermV2 serializeTerm() {
      return Schema.TermV2.newBuilder().setBool(this.value).build();
    }

    public String typeOf() {
      return "bool";
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
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

  public static final class Array extends Term implements Serializable {
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
      return "" + value;
    }

    public Schema.TermV2 serializeTerm() {
      Schema.Array.Builder s = Schema.Array.newBuilder();

      for (Term l : this.value) {
        s.addArray(l.serializeTerm());
      }

      return Schema.TermV2.newBuilder().setArray(s).build();
    }

    public String typeOf() {
      return "array";
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
      if (!term.hasArray()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected array"));
      } else {
        java.util.List<Term> values = new ArrayList<>();
        Schema.Array s = term.getArray();

        for (Schema.TermV2 l : s.getArrayList()) {
          var res = Term.deserializeEnumV2(l);
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

  public static final class Map extends Term implements Serializable {
    private final HashMap<MapKey, Term> value;

    public HashMap<MapKey, Term> value() {
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

    public Map(final HashMap<MapKey, Term> value) {
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
      return "" + value;
    }

    public Schema.TermV2 serializeTerm() {
      Schema.Map.Builder s = Schema.Map.newBuilder();

      for (java.util.Map.Entry<MapKey, Term> i : this.value.entrySet()) {
        Schema.MapEntry.Builder m = Schema.MapEntry.newBuilder();
        m.setKey(i.getKey().serializeMapKey());
        m.setValue(i.getValue().serializeTerm());
        s.addEntries(m);
      }

      return Schema.TermV2.newBuilder().setMap(s).build();
    }

    public String typeOf() {
      return "map";
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
      if (!term.hasMap()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected map"));
      }
      java.util.HashMap<MapKey, Term> values = new HashMap();
      Schema.Map s = term.getMap();

      for (Schema.MapEntry l : s.getEntriesList()) {
        var resKey = MapKey.deserializeMapKeyEnum(l.getKey());
        if (resKey.isErr()) {
          return Result.err(resKey.getErr());
        }
        var resValue = Term.deserializeEnumV2(l.getValue());
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
      HashMap<org.eclipse.biscuit.token.builder.MapKey, org.eclipse.biscuit.token.builder.Term> s =
          new HashMap<>();

      for (java.util.Map.Entry<MapKey, Term> i : this.value.entrySet()) {
        s.put(i.getKey().toMapKey(symbolTable), i.getValue().toTerm(symbolTable));
      }

      return new org.eclipse.biscuit.token.builder.Term.Map(s);
    }
  }

  public static final class Set extends Term implements Serializable {
    private final HashSet<Term> value;

    public HashSet<Term> value() {
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

    public Set(final HashSet<Term> value) {
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

    public Schema.TermV2 serializeTerm() {
      Schema.TermSet.Builder s = Schema.TermSet.newBuilder();

      for (Term l : this.value) {
        s.addSet(l.serializeTerm());
      }

      return Schema.TermV2.newBuilder().setSet(s).build();
    }

    public String typeOf() {
      return "set";
    }

    public static Result<Term, Error.FormatError> deserializeV2(Schema.TermV2 term) {
      if (!term.hasSet()) {
        return Result.err(
            new Error.FormatError.DeserializationError("invalid Term kind, expected set"));
      } else {
        java.util.HashSet<Term> values = new HashSet<>();
        Schema.TermSet s = term.getSet();

        for (Schema.TermV2 l : s.getSetList()) {
          var res = Term.deserializeEnumV2(l);
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
      HashSet<org.eclipse.biscuit.token.builder.Term> s = new HashSet<>();

      for (Term i : this.value) {
        s.add(i.toTerm(symbolTable));
      }

      return new org.eclipse.biscuit.token.builder.Term.Set(s);
    }
  }
}
