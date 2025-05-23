/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import io.vavr.Tuple2;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public final class RuleSet {
  private final HashMap<TrustedOrigins, List<Tuple2<Long, Rule>>> rules;

  public RuleSet() {
    rules = new HashMap<>();
  }

  public void add(Long origin, TrustedOrigins scope, Rule rule) {
    if (!rules.containsKey(scope)) {
      rules.put(scope, List.of(new Tuple2<>(origin, rule)));
    } else {
      rules.get(scope).add(new Tuple2<>(origin, rule));
    }
  }

  public RuleSet clone() {
    RuleSet newRules = new RuleSet();

    for (Map.Entry<TrustedOrigins, List<Tuple2<Long, Rule>>> entry : this.rules.entrySet()) {
      List<Tuple2<Long, Rule>> l = new ArrayList<>(entry.getValue());
      newRules.rules.put(entry.getKey(), l);
    }

    return newRules;
  }

  public Stream<Rule> stream() {
    return rules.entrySet().stream().flatMap(entry -> entry.getValue().stream().map(t -> t._2));
  }

  public void clear() {
    this.rules.clear();
  }

  public HashMap<TrustedOrigins, List<Tuple2<Long, Rule>>> getRules() {
    return this.rules;
  }
}
