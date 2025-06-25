/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import io.vavr.Tuple2;
import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.eclipse.biscuit.error.Error;

public final class World implements Serializable {
  private final FactSet facts;
  private final RuleSet rules;

  public void addFact(final Origin origin, final Fact fact) {
    this.facts.add(origin, fact);
  }

  public void addRule(Long origin, TrustedOrigins scope, Rule rule) {
    this.rules.add(origin, scope, rule);
  }

  public void clearRules() {
    this.rules.clear();
  }

  public void run(final SymbolTable symbolTable) throws Error {
    this.run(new RunLimits(), symbolTable);
  }

  public void run(RunLimits limits, final SymbolTable symbolTable) throws Error {
    int iterations = 0;
    Instant limit = Instant.now().plus(limits.getMaxTime());

    while (true) {
      final FactSet newFacts = new FactSet();

      for (Map.Entry<TrustedOrigins, List<Tuple2<Long, Rule>>> entry :
          this.rules.getRules().entrySet()) {
        for (Tuple2<Long, Rule> t : entry.getValue()) {
          Supplier<Stream<Tuple2<Origin, Fact>>> factsSupplier =
              () -> this.facts.stream(entry.getKey());

          var stream = t._2.apply(factsSupplier, t._1, symbolTable);
          for (var it = stream.iterator(); it.hasNext(); ) {
            var res = it.next();
            if (Instant.now().compareTo(limit) >= 0) {
              throw new Error.Timeout();
            }

            if (res.isOk()) {
              Tuple2<Origin, Fact> t2 = res.getOk();
              newFacts.add(t2._1, t2._2);
            } else {
              throw res.getErr();
            }
          }
        }
      }

      final int len = this.facts.size();
      this.facts.merge(newFacts);

      if (this.facts.size() == len) {
        return;
      }

      if (this.facts.size() >= limits.getMaxFacts()) {
        throw new Error.TooManyFacts();
      }

      iterations += 1;
      if (iterations >= limits.getMaxIterations()) {
        throw new Error.TooManyIterations();
      }
    }
  }

  public FactSet getFacts() {
    return this.facts;
  }

  public RuleSet getRules() {
    return this.rules;
  }

  public FactSet queryRule(
      final Rule rule, Long origin, TrustedOrigins scope, SymbolTable symbolTable) throws Error {
    final FactSet newFacts = new FactSet();

    Supplier<Stream<Tuple2<Origin, Fact>>> factsSupplier = () -> this.facts.stream(scope);

    var stream = rule.apply(factsSupplier, origin, symbolTable);
    for (var it = stream.iterator(); it.hasNext(); ) {
      var res = it.next();

      if (res.isOk()) {
        Tuple2<Origin, Fact> t2 = res.getOk();
        newFacts.add(t2._1, t2._2);
      } else {
        throw res.getErr();
      }
    }

    return newFacts;
  }

  public boolean queryMatch(
      final Rule rule, Long origin, TrustedOrigins scope, SymbolTable symbolTable) throws Error {
    return rule.findMatch(this.facts, origin, scope, symbolTable);
  }

  public boolean queryMatchAll(final Rule rule, TrustedOrigins scope, SymbolTable symbolTable)
      throws Error {
    return rule.checkMatchAll(this.facts, scope, symbolTable);
  }

  public World() {
    this.facts = new FactSet();
    this.rules = new RuleSet();
  }

  public World(FactSet facts) {
    this.facts = facts.clone();
    this.rules = new RuleSet();
  }

  public World(FactSet facts, RuleSet rules) {
    this.facts = facts.clone();
    this.rules = rules.clone();
  }

  public World(World w) {
    this.facts = w.facts.clone();
    this.rules = w.rules.clone();
  }

  public String print(SymbolTable symbolTable) {
    StringBuilder s = new StringBuilder();

    s.append("World {\n\t\tfacts: [");
    for (Map.Entry<Origin, HashSet<Fact>> entry : this.facts.facts().entrySet()) {
      s.append("\n\t\t\t" + entry.getKey() + ":");
      for (Fact f : entry.getValue()) {
        s.append("\n\t\t\t\t");
        s.append(symbolTable.formatFact(f));
      }
    }

    s.append("\n\t\t]\n\t\trules: [");
    for (Iterator<Rule> it = this.rules.stream().iterator(); it.hasNext(); ) {
      Rule r = it.next();
      s.append("\n\t\t\t");
      s.append(symbolTable.formatRule(r));
    }

    s.append("\n\t\t]\n\t}");

    return s.toString();
  }
}
