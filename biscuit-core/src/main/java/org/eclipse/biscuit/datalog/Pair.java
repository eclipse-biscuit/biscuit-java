/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.util.Comparator;
import java.util.Objects;

public final class Pair<T1, T2> {
  public final T1 _1;
  public final T2 _2;

  public Pair(T1 t1, T2 t2) {
    this._1 = t1;
    this._2 = t2;
  }

  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (!(o instanceof Pair)) {
      return false;
    }
    Pair<?, ?> that = (Pair<?, ?>) o;
    return Objects.equals(this._1, that._1) && Objects.equals(this._2, that._2);
  }

  public int hashCode() {
    int result = 1;
    result = 31 * result + _1.hashCode();
    result = 31 * result + _2.hashCode();
    return result;
  }

  public String toString() {
    return "(" + this._1 + ", " + this._2 + ")";
  }

  /** Lexicographic order: by the first element with {@code ct1}, then by the second with {@code ct2}. */
  public static <U1, U2> Comparator<Pair<U1, U2>> comparator(
      Comparator<? super U1> ct1, Comparator<? super U2> ct2) {
    return Comparator.comparing((Pair<U1, U2> p) -> p._1, ct1)
        .thenComparing((Pair<U1, U2> p) -> p._2, ct2);
  }

  /** Lexicographic order using the natural order of both elements. */
  public static <U1 extends Comparable<? super U1>, U2 extends Comparable<? super U2>>
      Comparator<Pair<U1, U2>> naturalComparator() {
    return comparator(Comparator.<U1>naturalOrder(), Comparator.<U2>naturalOrder());
  }
}
