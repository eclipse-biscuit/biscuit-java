/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

public final class Combinator implements Serializable, Iterator<Pair<Origin, Map<Long, Term>>> {
  private MatchedVariables variables;
  private final Supplier<Stream<Pair<Origin, Fact>>> allFacts;
  private final List<Predicate> predicates;
  private final Iterator<Pair<Origin, Fact>> currentFacts;
  private Combinator currentIt;
  private final SymbolTable symbolTable;

  private Origin currentOrigin;

  private Optional<Pair<Origin, Map<Long, Term>>> nextElement;

  @Override
  public boolean hasNext() {
    if (this.nextElement != null && this.nextElement.isPresent()) {
      return true;
    }
    this.nextElement = getNext();
    return this.nextElement.isPresent();
  }

  @Override
  public Pair<Origin, Map<Long, Term>> next() {
    if (this.nextElement == null || !this.nextElement.isPresent()) {
      this.nextElement = getNext();
    }
    if (this.nextElement == null || !this.nextElement.isPresent()) {
      throw new NoSuchElementException();
    } else {
      Pair<Origin, Map<Long, Term>> t = this.nextElement.get();
      this.nextElement = Optional.empty();
      return t;
    }
  }

  public Optional<Pair<Origin, Map<Long, Term>>> getNext() {
    if (this.predicates.isEmpty()) {
      final Optional<Map<Long, Term>> vOpt = this.variables.complete();
      if (vOpt.isEmpty()) {
        return Optional.empty();
      } else {
        Map<Long, Term> variables = vOpt.get();
        // if there were no predicates,
        // we should return a value, but only once. To prevent further
        // successful calls, we create a set of variables that cannot
        // possibly be completed, so the next call will fail
        Set<Long> set = new HashSet<>();
        set.add((long) 0);

        this.variables = new MatchedVariables(set);
        return Optional.of(new Pair<>(new Origin(), variables));
      }
    }

    while (true) {
      if (this.currentIt == null) {
        Predicate predicate = this.predicates.get(0);

        while (true) {
          // we iterate over the facts that match the current predicate
          if (this.currentFacts.hasNext()) {
            final Pair<Origin, Fact> t = this.currentFacts.next();
            Origin currentOrigin = t._1.clone();
            Fact fact = t._2;

            // create a new MatchedVariables in which we fix variables we could unify from our first
            // predicate and the current fact
            MatchedVariables vars = this.variables.clone();
            boolean matchTerms = true;

            // we know the fact matches the predicate's format so they have the same number of terms
            // fill the MatchedVariables before creating the next combinator
            for (int i = 0; i < predicate.terms().size(); ++i) {
              final Term term = predicate.terms().get(i);
              if (term instanceof Term.Variable) {
                final long key = ((Term.Variable) term).value();
                final Term value = fact.predicate().terms().get(i);

                if (!vars.insert(key, value)) {
                  matchTerms = false;
                }
                if (!matchTerms) {
                  break;
                }
              }
            }

            // the fact did not match the predicate, try the next one
            if (!matchTerms) {
              continue;
            }

            // there are no more predicates to check
            if (this.predicates.size() == 1) {
              final Optional<Map<Long, Term>> vOpt = vars.complete();
              if (vOpt.isEmpty()) {
                continue;
              } else {
                return Optional.of(new Pair<>(currentOrigin, vOpt.get()));
              }
            } else {
              this.currentOrigin = currentOrigin;
              // we found a matching fact, we create a new combinator over the rest of the
              // predicates
              // no need to copy all the expressions at all levels
              this.currentIt =
                  new Combinator(
                      vars,
                      predicates.subList(1, predicates.size()),
                      this.allFacts,
                      this.symbolTable);
            }
            break;

          } else {
            return Optional.empty();
          }
        }
      }

      if (this.currentIt == null) {
        return Optional.empty();
      }

      Optional<Pair<Origin, Map<Long, Term>>> opt = this.currentIt.getNext();

      if (opt.isPresent()) {
        Pair<Origin, Map<Long, Term>> t = opt.get();
        return Optional.of(new Pair<>(t._1.union(currentOrigin), t._2));
      } else {
        currentOrigin = null;
        currentIt = null;
      }
    }
  }

  public Combinator(
      final MatchedVariables variables,
      final List<Predicate> predicates,
      Supplier<Stream<Pair<Origin, Fact>>> allFacts,
      final SymbolTable symbolTable) {
    this.variables = variables;
    this.allFacts = allFacts;
    this.currentIt = null;
    this.predicates = predicates;
    this.currentFacts =
        allFacts.get().filter((tuple) -> tuple._2.matchPredicate(predicates.get(0))).iterator();
    this.symbolTable = symbolTable;
    this.currentOrigin = null;
    this.nextElement = null;
  }
}
