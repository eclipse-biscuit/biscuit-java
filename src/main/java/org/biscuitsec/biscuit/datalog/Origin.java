package org.biscuitsec.biscuit.datalog;

import java.util.HashSet;
import java.util.Objects;

public class Origin {
    public HashSet<Long> inner;

    public Origin() {
        inner = new HashSet<>();
    }

    private Origin(HashSet<Long> inner) {
        this.inner = inner;
    }

    public Origin(Long i) {
        this.inner = new HashSet<>();
        this.inner.add(i);
    }

    public Origin(int i) {
        this.inner = new HashSet<>();
        this.inner.add((long)i);
    }

    public static Origin authorizer() {
        return new Origin(Long.MAX_VALUE);
    }
    public void add(int i) {
        inner.add((long) i);
    }
    public void add(long i) {
        inner.add(i);
    }

    public Origin union(Origin other) {
        Origin o = this.clone();
        o.inner.addAll(other.inner);
        return o;
    }

    public Origin clone() {
        final HashSet<Long> newInner = new HashSet<>(this.inner);
        return new Origin(newInner);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Origin origin = (Origin) o;

        return Objects.equals(inner, origin.inner);
    }

    @Override
    public int hashCode() {
        return inner != null ? inner.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "Origin{" +
                "inner=" + inner +
                '}';
    }
}
