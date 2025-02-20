package org.biscuitsec.biscuit.datalog;

import io.vavr.Tuple2;
import io.vavr.control.Option;

import java.io.Serializable;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

public final class Combinator implements Serializable, Iterator<Tuple2<Origin, Map<Long, Term>>> {
   private MatchedVariables variables;
   private final Supplier<Stream<Tuple2<Origin, Fact>>> allFacts;
   private final List<Predicate> predicates;
   private final Iterator<Tuple2<Origin, Fact>> currentFacts;
   private Combinator currentIt;
   private final SymbolTable symbols;

   private Origin currentOrigin;

   private Option<Tuple2<Origin, Map<Long, Term>>> nextElement;

   @Override
   public boolean hasNext() {
      if (this.nextElement != null && this.nextElement.isDefined()) {
         return true;
      }
      this.nextElement = getNext();
      return this.nextElement.isDefined();
   }

   @Override
   public Tuple2<Origin, Map<Long, Term>> next() {
      if (this.nextElement == null || !this.nextElement.isDefined()) {
         this.nextElement = getNext();
      }
      if (this.nextElement == null || !this.nextElement.isDefined()) {
         throw new NoSuchElementException();
      } else {
         Tuple2<Origin, Map<Long, Term>> t = this.nextElement.get();
         this.nextElement = Option.none();
         return t;
      }
   }

   public Option<Tuple2<Origin, Map<Long, Term>>> getNext() {
      if (this.predicates.isEmpty()) {
         final Option<Map<Long, Term>> vOpt = this.variables.complete();
         if (vOpt.isEmpty()) {
            return Option.none();
         } else {
            Map<Long, Term> variables = vOpt.get();
            // if there were no predicates,
            // we should return a value, but only once. To prevent further
            // successful calls, we create a set of variables that cannot
            // possibly be completed, so the next call will fail
            Set<Long> set = new HashSet<>();
            set.add((long) 0);

            this.variables = new MatchedVariables(set);
            return Option.some(new Tuple2<>(new Origin(), variables));
         }
      }

      while (true) {
         if (this.currentIt == null) {
            Predicate predicate = this.predicates.get(0);

            while (true) {
               // we iterate over the facts that match the current predicate
               if (this.currentFacts.hasNext()) {
                  final Tuple2<Origin, Fact> t = this.currentFacts.next();
                  Origin currentOrigin = t._1.clone();
                  Fact fact = t._2;

                  // create a new MatchedVariables in which we fix variables we could unify from our first predicate and the current fact
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
                     final Option<Map<Long, Term>> vOpt = vars.complete();
                     if (vOpt.isEmpty()) {
                        continue;
                     } else {
                        return Option.some(new Tuple2<>(currentOrigin, vOpt.get()));
                     }
                  } else {
                     this.currentOrigin = currentOrigin;
                     // we found a matching fact, we create a new combinator over the rest of the predicates
                     // no need to copy all the expressions at all levels
                     this.currentIt = new Combinator(vars, predicates.subList(1, predicates.size()), this.allFacts, this.symbols);
                  }
                  break;

               } else {
                  return Option.none();
               }
            }
         }

         if (this.currentIt == null) {
            return Option.none();
         }

         Option<Tuple2<Origin, Map<Long, Term>>> opt = this.currentIt.getNext();

         if (opt.isDefined()) {
            Tuple2<Origin, Map<Long, Term>> t = opt.get();
            return Option.some(new Tuple2<>(t._1.union(currentOrigin), t._2));
         } else {
            currentOrigin = null;
            currentIt = null;
         }
      }
   }


   public Combinator(final MatchedVariables variables, final List<Predicate> predicates,
                     Supplier<Stream<Tuple2<Origin, Fact>>> all_facts, final SymbolTable symbols) {
      this.variables = variables;
      this.allFacts = all_facts;
      this.currentIt = null;
      this.predicates = predicates;
      this.currentFacts = all_facts.get().filter((tuple) -> tuple._2.match_predicate(predicates.get(0))).iterator();
      this.symbols = symbols;
      this.currentOrigin = null;
      this.nextElement = null;
   }
}
