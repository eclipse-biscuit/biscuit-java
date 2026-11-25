/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;
import java.util.stream.Collectors;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.DeserializationLimit;
import org.eclipse.biscuit.token.builder.Utils;

public final class Predicate {
  private final long name;
  private final List<Term> terms;

  public static Comparator<Predicate> comparator =
      Comparator.comparing(Predicate::name)
          .thenComparing(Predicate::terms, Utils.listComparator(Term.comparator));

  public long name() {
    return this.name;
  }

  public List<Term> terms() {
    return this.terms;
  }

  public ListIterator<Term> idsIterator() {
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
    final List<Term> terms = new ArrayList<>(this.terms);
    return new Predicate(this.name, terms);
  }

  public Predicate(final long name, final List<Term> terms) {
    this.name = name;
    this.terms = terms;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Predicate predicate = (Predicate) o;
    return name == predicate.name && Objects.equals(terms, predicate.terms);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, terms);
  }

  @Override
  public String toString() {
    return this.name
        + "("
        + this.terms.stream()
            .map((i) -> (i == null) ? "(null)" : i.toString())
            .collect(Collectors.joining(", "))
        + ")";
  }

  public Schema.Predicate serialize() {
    Schema.Predicate.Builder builder = Schema.Predicate.newBuilder().setName(this.name);

    for (Term term : this.terms) {
      builder.addTerms(term.serializeTerm());
    }

    return builder.build();
  }

  public static Result<Predicate, Error.FormatError> deserialize(
      Schema.Predicate predicate, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
    if (predicate.getTermsCount() > limits.getMaxTermsPerPredicate()) {
      return Result.err(
          new Error.FormatError.DeserializationLimitError(
              Error.FormatError.DeserializationLimitError.Reason.TOO_MANY_TERMS));
    }
    var nameError = limits.checkName(symbols, predicate.getName());
    if (nameError != null) {
      return Result.err(nameError);
    }

    ArrayList<Term> terms = new ArrayList<>();
    for (Schema.Term id : predicate.getTermsList()) {
      var res = Term.deserializeEnum(id, limits, symbols);
      if (res.isErr()) {
        return Result.err(res.getErr());
      } else {
        terms.add(res.getOk());
      }
    }

    return Result.ok(new Predicate(predicate.getName(), terms));
  }
}
