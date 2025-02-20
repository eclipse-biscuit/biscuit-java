package org.biscuitsec.biscuit.token.builder;

import org.biscuitsec.biscuit.datalog.SymbolTable;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;

public abstract class Term {
    abstract public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols);
    static public Term convertFrom(org.biscuitsec.biscuit.datalog.Term id, SymbolTable symbols) {
        return id.toTerm(symbols);
    }

    public static class Str extends Term {
        final String value;

        public Str(String value) {
            this.value = value;
        }

        @Override
        public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols) {
            return new org.biscuitsec.biscuit.datalog.Term.Str(symbols.insert(this.value));
        }

        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return "\""+value+"\"";
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Str s = (Str) o;
            return Objects.equals(value, s.value);
        }

        @Override
        public int hashCode() {
            return value.hashCode();
        }
    }

    public static class Variable extends Term {
        final String value;

        public Variable(String value) {
            this.value = value;
        }

        @Override
        public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols) {
            return new org.biscuitsec.biscuit.datalog.Term.Variable(symbols.insert(this.value));
        }

        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return "$"+value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Variable variable = (Variable) o;

            return value.equals(variable.value);
        }

        @Override
        public int hashCode() {
            return value.hashCode();
        }
    }

    public static class Integer extends Term {
        final long value;

        public Integer(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }

        @Override
        public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols) {
            return new org.biscuitsec.biscuit.datalog.Term.Integer(this.value);
        }

        @Override
        public String toString() {
            return String.valueOf(value);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Integer integer = (Integer) o;

            return value == integer.value;
        }

        @Override
        public int hashCode() {
            return Long.hashCode(value);
        }
    }

    public static class Bytes extends Term {
        final byte[] value;

        public Bytes(byte[] value) {
            this.value = value;
        }

        @Override
        public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols) {
            return new org.biscuitsec.biscuit.datalog.Term.Bytes(this.value);
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
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Bytes bytes = (Bytes) o;

            return Arrays.equals(value, bytes.value);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(value);
        }
    }

    public static class Date extends Term {
        final long value;

        public Date(long value) {
            this.value = value;
        }

        @Override
        public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols) {
            return new org.biscuitsec.biscuit.datalog.Term.Date(this.value);
        }

        public long getValue() {
            return value;
        }

        @Override
        public String toString() {
            DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ISO_INSTANT;
            return Instant.ofEpochSecond(value).atOffset(ZoneOffset.ofTotalSeconds(0)).format(dateTimeFormatter);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Date date = (Date) o;

            return value == date.value;
        }

        @Override
        public int hashCode() {
            return Long.hashCode(value);
        }
    }

    public static class Bool extends Term {
        final boolean value;

        public Bool(boolean value) {
            this.value = value;
        }

        @Override
        public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols) {
            return new org.biscuitsec.biscuit.datalog.Term.Bool(this.value);
        }

        public boolean getValue() {
            return value;
        }

        @Override
        public String toString() {
            if(value) {
                return "true";
            } else {
                return "false";
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Bool bool = (Bool) o;

            return value == bool.value;
        }

        @Override
        public int hashCode() {
            return Boolean.hashCode(value);
        }
    }

    public static class Set extends Term {
        final java.util.Set<Term> value;

        public Set(java.util.Set<Term> value) {
            this.value = value;
        }

        @Override
        public org.biscuitsec.biscuit.datalog.Term convert(SymbolTable symbols) {
            HashSet<org.biscuitsec.biscuit.datalog.Term> s = new HashSet<>();

            for(Term t: this.value) {
                s.add(t.convert(symbols));
            }

            return new org.biscuitsec.biscuit.datalog.Term.Set(s);
        }

        public java.util.Set<Term> getValue() {
            return Collections.unmodifiableSet(value);
        }

        @Override
        public String toString() {
            return value.toString();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Set set = (Set) o;

            return Objects.equals(value, set.value);
        }

        @Override
        public int hashCode() {
            return value != null ? value.hashCode() : 0;
        }
    }
}
