/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public final class FactSet {
  /** facts grouped by (predicate name, arity), then by origin */
  private final HashMap<Pair<Long, Integer>, HashMap<Origin, HashSet<Fact>>> facts;

  public FactSet() {
    facts = new HashMap<>();
  }

  public FactSet(Origin o, HashSet<Fact> factSet) {
    facts = new HashMap<>();
    for (Fact fact : factSet) {
      add(o, fact);
    }
  }

  public Map<Origin, List<Fact>> byOrigin() {
    Map<Origin, List<Fact>> origins = new HashMap<>();
    for (HashMap<Origin, HashSet<Fact>> group : facts.values()) {
      for (Map.Entry<Origin, HashSet<Fact>> entry : group.entrySet()) {
        origins.computeIfAbsent(entry.getKey(), k -> new ArrayList<>()).addAll(entry.getValue());
      }
    }
    return origins;
  }

  private static Pair<Long, Integer> keyOf(Predicate predicate) {
    return new Pair<>(predicate.name(), predicate.terms().size());
  }

  public void add(Origin origin, Fact fact) {
    Pair<Long, Integer> key = keyOf(fact.predicate());
    HashMap<Origin, HashSet<Fact>> group = facts.computeIfAbsent(key, k -> new HashMap<>());
    group.computeIfAbsent(origin, k -> new HashSet<>()).add(fact);
  }

  public int size() {
    int size = 0;
    for (HashMap<Origin, HashSet<Fact>> group : facts.values()) {
      for (HashSet<Fact> h : group.values()) {
        size += h.size();
      }
    }

    return size;
  }

  public FactSet clone() {
    FactSet newFacts = new FactSet();

    for (Map.Entry<Pair<Long, Integer>, HashMap<Origin, HashSet<Fact>>> group :
        this.facts.entrySet()) {
      HashMap<Origin, HashSet<Fact>> newGroup = new HashMap<>();
      for (Map.Entry<Origin, HashSet<Fact>> entry : group.getValue().entrySet()) {
        newGroup.put(entry.getKey(), new HashSet<>(entry.getValue()));
      }
      newFacts.facts.put(group.getKey(), newGroup);
    }

    return newFacts;
  }

  public void merge(FactSet other) {
    for (Map.Entry<Pair<Long, Integer>, HashMap<Origin, HashSet<Fact>>> group :
        other.facts.entrySet()) {
      HashMap<Origin, HashSet<Fact>> ownGroup =
          facts.computeIfAbsent(group.getKey(), k -> new HashMap<>());
      for (Map.Entry<Origin, HashSet<Fact>> entry : group.getValue().entrySet()) {
        ownGroup.computeIfAbsent(entry.getKey(), k -> new HashSet<>()).addAll(entry.getValue());
      }
    }
  }

  /** trusted facts sharing the predicate's name and arity, the terms are not checked */
  public Stream<Pair<Origin, Fact>> stream(Predicate predicate, TrustedOrigins blockIds) {
    HashMap<Origin, HashSet<Fact>> group = facts.get(keyOf(predicate));
    if (group == null) {
      return Stream.empty();
    }
    return group.entrySet().stream()
        .filter(entry -> blockIds.contains(entry.getKey()))
        .flatMap(entry -> entry.getValue().stream().map(fact -> new Pair<>(entry.getKey(), fact)));
  }

  public Stream<Fact> stream() {
    return facts.values().stream()
        .flatMap(group -> group.values().stream())
        .flatMap(HashSet::stream);
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
    for (Map.Entry<Origin, List<Fact>> entry : this.byOrigin().entrySet()) {
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
