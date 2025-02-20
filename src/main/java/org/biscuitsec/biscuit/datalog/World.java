package org.biscuitsec.biscuit.datalog;

import org.biscuitsec.biscuit.error.Error;
import io.vavr.Tuple2;
import io.vavr.control.Either;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class World implements Serializable {
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

   public void run(final SymbolTable symbols) throws Error {
      this.run(new RunLimits(), symbols);
   }

   public void run(RunLimits limits, final SymbolTable symbols) throws Error {
      int iterations = 0;
      Instant limit = Instant.now().plus(limits.maxTime);

      while(true) {
         final FactSet newFacts = new FactSet();

         for(Map.Entry<TrustedOrigins, List<Tuple2<Long, Rule>>> entry: this.rules.rules.entrySet()) {
            for(Tuple2<Long, Rule> t: entry.getValue()) {
               Supplier<Stream<Tuple2<Origin, Fact>>> factsSupplier = () -> this.facts.stream(entry.getKey());

               Stream<Either<Error, Tuple2<Origin, Fact>>> stream =  t._2.apply(factsSupplier, t._1, symbols);
                for (Iterator<Either<Error, Tuple2<Origin, Fact>>> it = stream.iterator(); it.hasNext(); ) {
                    Either<Error, Tuple2<Origin, Fact>> res = it.next();
                    if(Instant.now().compareTo(limit) >= 0) {
                       throw new Error.Timeout();
                    }

                    if(res.isRight()) {
                       Tuple2<Origin, Fact> t2 = res.get();
                       newFacts.add(t2._1, t2._2);
                    } else {
                        throw res.getLeft();
                    }
                }
            }
         }

         final int len = this.facts.size();
         this.facts.merge(newFacts);

         if (this.facts.size() == len) {
            return ;
         }

         if (this.facts.size() >= limits.maxFacts) {
            throw new Error.TooManyFacts();
         }

         iterations += 1;
         if(iterations >= limits.maxIterations) {
            throw new Error.TooManyIterations();
         }
      }
   }

   public final FactSet facts() {
      return this.facts;
   }

   public RuleSet rules() {
      return this.rules;
   }

   public final FactSet queryRule(final Rule rule, Long origin, TrustedOrigins scope, SymbolTable symbols) throws Error {
      final FactSet newFacts = new FactSet();

      Supplier<Stream<Tuple2<Origin, Fact>>> factsSupplier = () -> this.facts.stream(scope);

      Stream<Either<Error, Tuple2<Origin, Fact>>> stream = rule.apply(factsSupplier, origin, symbols);
      for (Iterator<Either<Error, Tuple2<Origin, Fact>>> it = stream.iterator(); it.hasNext(); ) {
         Either<Error, Tuple2<Origin, Fact>> res = it.next();

         if (res.isRight()) {
            Tuple2<Origin, Fact> t2 = res.get();
            newFacts.add(t2._1, t2._2);
         } else {
             throw res.getLeft();
         }
      }

      return newFacts;
   }

   public final boolean queryMatch(final Rule rule, Long origin, TrustedOrigins scope, SymbolTable symbols) throws Error {
      return rule.findMatch(this.facts, origin, scope, symbols);
   }

   public final boolean queryMatchAll(final Rule rule, TrustedOrigins scope, SymbolTable symbols) throws Error {
      return rule.checkMatchAll(this.facts, scope, symbols);
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
      for(Map.Entry<Origin, HashSet<Fact>> entry: this.facts.facts().entrySet()) {
         s.append("\n\t\t\t"+entry.getKey()+":");
         for(Fact f: entry.getValue()) {
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
