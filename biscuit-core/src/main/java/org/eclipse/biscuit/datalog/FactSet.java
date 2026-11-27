/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

public final class FactSet {
  /** facts grouped by (predicate name, arity), then by origin */
  private final SortedMap<Pair<Long, Integer>, SortedMap<Origin, SortedSet<Fact>>> facts;

  private static final Comparator<Pair<Long, Integer>> KEY_COMPARATOR = Pair.naturalComparator();

  public FactSet() {
    facts = new TreeMap<>(KEY_COMPARATOR);
  }

  public FactSet(Origin o, SortedSet<Fact> factSet) {
    facts = new TreeMap<>(KEY_COMPARATOR);
    for (Fact fact : factSet) {
      add(o, fact);
    }
  }

  public Map<Origin, List<Fact>> byOrigin() {
    Map<Origin, List<Fact>> origins = new TreeMap<>(Origin.comparator);
    for (SortedMap<Origin, SortedSet<Fact>> group : facts.values()) {
      for (Map.Entry<Origin, SortedSet<Fact>> entry : group.entrySet()) {
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
    SortedMap<Origin, SortedSet<Fact>> group =
        facts.computeIfAbsent(key, k -> new TreeMap<>(Origin.comparator));
    group.computeIfAbsent(origin, k -> new TreeSet<>(Fact.comparator)).add(fact);
  }

  public int size() {
    int size = 0;
    for (SortedMap<Origin, SortedSet<Fact>> group : facts.values()) {
      for (SortedSet<Fact> h : group.values()) {
        size += h.size();
      }
    }

    return size;
  }

  public FactSet clone() {
    FactSet newFacts = new FactSet();

    for (Map.Entry<Pair<Long, Integer>, SortedMap<Origin, SortedSet<Fact>>> group :
        this.facts.entrySet()) {
      SortedMap<Origin, SortedSet<Fact>> newGroup = new TreeMap<>(Origin.comparator);
      for (Map.Entry<Origin, SortedSet<Fact>> entry : group.getValue().entrySet()) {
        newGroup.put(entry.getKey(), new TreeSet<>(entry.getValue()));
      }
      newFacts.facts.put(group.getKey(), newGroup);
    }

    return newFacts;
  }

  public void merge(FactSet other) {
    for (Map.Entry<Pair<Long, Integer>, SortedMap<Origin, SortedSet<Fact>>> group :
        other.facts.entrySet()) {
      SortedMap<Origin, SortedSet<Fact>> ownGroup =
          facts.computeIfAbsent(group.getKey(), k -> new TreeMap<>(Origin.comparator));
      for (Map.Entry<Origin, SortedSet<Fact>> entry : group.getValue().entrySet()) {
        ownGroup
            .computeIfAbsent(entry.getKey(), k -> new TreeSet<>(Fact.comparator))
            .addAll(entry.getValue());
      }
    }
  }

  /** trusted facts sharing the predicate's name and arity, the terms are not checked */
  public Stream<Pair<Origin, Fact>> stream(Predicate predicate, TrustedOrigins blockIds) {
    SortedMap<Origin, SortedSet<Fact>> group = facts.get(keyOf(predicate));
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
        .flatMap(SortedSet::stream);
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
