package org.biscuitsec.biscuit.datalog;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.error.Error;
import io.vavr.control.Either;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;
import java.util.stream.Collectors;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

public final class Predicate implements Serializable {
   private final long name;
   private final List<Term> terms;

   public long name() {
      return this.name;
   }

   public final List<Term> terms() {
      return this.terms;
   }

   public final ListIterator<Term> ids_iterator() {
      return this.terms.listIterator();
   }

   public boolean match(final Predicate rulePredicate) {
      if (this.name != rulePredicate.name) {
         return false;
      }
      if (this.terms.size() != rulePredicate.terms.size()) {
         return false;
      }
      for (int i = 0; i < this.terms.size(); ++i) {
         if (!this.terms.get(i).match(rulePredicate.terms.get(i))) {
            return false;
         }
      }
      return true;
   }

   public Predicate clone() {
      final List<Term> terms = new ArrayList<>();
      terms.addAll(this.terms);
      return new Predicate(this.name, terms);
   }

   public Predicate(final long name, final List<Term> terms) {
      this.name = name;
      this.terms = terms;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      Predicate predicate = (Predicate) o;
      return name == predicate.name &&
            Objects.equals(terms, predicate.terms);
   }

   @Override
   public int hashCode() {
      return Objects.hash(name, terms);
   }

   @Override
   public String toString() {
      return this.name + "(" + String.join(", ", this.terms.stream().map((i) -> (i == null) ? "(null)" : i.toString()).collect(Collectors.toList())) + ")";
   }

   public Schema.PredicateV2 serialize() {
      Schema.PredicateV2.Builder builder = Schema.PredicateV2.newBuilder()
              .setName(this.name);

      for (int i = 0; i < this.terms.size(); i++) {
         builder.addTerms(this.terms.get(i).serialize());
      }

      return builder.build();
   }

   static public Either<Error.FormatError, Predicate> deserializeV2(Schema.PredicateV2 predicate) {
      ArrayList<Term> terms = new ArrayList<>();
      for (Schema.TermV2 id: predicate.getTermsList()) {
         Either<Error.FormatError, Term> res = Term.deserialize_enumV2(id);
         if(res.isLeft()) {
            Error.FormatError e = res.getLeft();
            return Left(e);
         } else {
            terms.add(res.get());
         }
      }

      return Right(new Predicate(predicate.getName(), terms));
   }
}
