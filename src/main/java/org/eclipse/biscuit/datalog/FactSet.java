/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.stream.Stream;

public final class FactSet {
  private final HashMap<Origin, HashSet<Fact>> facts;

  public FactSet() {
    facts = new HashMap<>();
  }

  public FactSet(Origin o, HashSet<Fact> factSet) {
    facts = new HashMap<>();
    facts.put(o, factSet);
  }

  public HashMap<Origin, HashSet<Fact>> facts() {
    return this.facts;
  }

  public void add(Origin origin, Fact fact) {
    if (!facts.containsKey(origin)) {
      facts.put(origin, new HashSet<>());
    }
    facts.get(origin).add(fact);
  }

  public int size() {
    int size = 0;
    for (HashSet<Fact> h : facts.values()) {
      size += h.size();
    }

    return size;
  }

  public FactSet clone() {
    FactSet newFacts = new FactSet();

    for (Map.Entry<Origin, HashSet<Fact>> entry : this.facts.entrySet()) {
      HashSet<Fact> h = new HashSet<>(entry.getValue());
      newFacts.facts.put(entry.getKey(), h);
    }

    return newFacts;
  }

  public void merge(FactSet other) {
    for (Map.Entry<Origin, HashSet<Fact>> entry : other.facts.entrySet()) {
      if (!facts.containsKey(entry.getKey())) {
        facts.put(entry.getKey(), entry.getValue());
      } else {
        facts.get(entry.getKey()).addAll(entry.getValue());
      }
    }
  }

  public Stream stream(TrustedOrigins blockIds) {
    return facts.entrySet().stream()
        .filter(
            entry -> {
              Origin o = entry.getKey();
              return blockIds.contains(o);
            })
        .flatMap(entry -> entry.getValue().stream().map(fact -> new Pair<>(entry.getKey(), fact)));
  }

  public Stream<Fact> stream() {
    return facts.entrySet().stream().flatMap(entry -> entry.getValue().stream());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    FactSet factSet = (FactSet) o;

    return facts.equals(factSet.facts);
  }

  @Override
  public int hashCode() {
    return facts.hashCode();
  }

  @Override
  public String toString() {
    StringBuilder res = new StringBuilder("FactSet {");
    for (Map.Entry<Origin, HashSet<Fact>> entry : this.facts.entrySet()) {
      res.append("\n\t").append(entry.getKey()).append("[");
      for (Fact fact : entry.getValue()) {
        res.append("\n\t\t").append(fact);
      }
      res.append("\n]");
    }
    res.append("\n}");

    return res.toString();
  }
}
