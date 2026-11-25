/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

public final class Origin {
  private final TreeSet<Long> blockIds;

  public Origin() {
    this.blockIds = new TreeSet<>();
  }

  public Origin(Long i) {
    this.blockIds = new TreeSet<>();
    this.blockIds.add(i);
  }

  public Origin(int i) {
    this.blockIds = new TreeSet<>();
    this.blockIds.add((long) i);
  }

  public static Origin authorizer() {
    return new Origin(Long.MAX_VALUE);
  }

  public void add(int i) {
    blockIds.add((long) i);
  }

  public void add(long i) {
    blockIds.add(i);
  }

  public boolean addAll(final Collection<Long> newBlockIds) {
    return this.blockIds.addAll(newBlockIds);
  }

  public Origin union(Origin other) {
    Origin o = this.clone();
    o.blockIds.addAll(other.blockIds);
    return o;
  }

  public boolean containsAll(Origin other) {
    return this.blockIds.containsAll(other.blockIds);
  }

  @Override
  protected Origin clone() {
    final Origin newOrigin = new Origin();
    newOrigin.addAll(this.blockIds);
    return newOrigin;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Origin origin = (Origin) o;

    return Objects.equals(blockIds, origin.blockIds);
  }

  public static Comparator<Origin> comparator =
      new Comparator<Origin>() {
        @Override
        public int compare(Origin o1, Origin o2) {
          if (o1 == null && o2 == null) {
            return 0;
          } else if (o1 == null) {
            return -1;
          } else if (o2 == null) {
            return 1;
          } else {
            var o1it = o1.blockIds.iterator();
            var o2it = o2.blockIds.iterator();
            var c = 0;
            while (c == 0) {
              if (o1it.hasNext() && o2it.hasNext()) {
                c = Long.compare(o1it.next(), o2it.next());
              } else if (o1it.hasNext()) {
                c = 1;
              } else if (o2it.hasNext()) {
                c = -1;
              } else {
                return c;
              }
            }
            return c;
          }
        }
      };

  @Override
  public int hashCode() {
    return blockIds != null ? blockIds.hashCode() : 0;
  }

  @Override
  public String toString() {
    return "Origin{inner=" + blockIds + '}';
  }

  public Set<Long> blockIds() {
    return Collections.unmodifiableSet(this.blockIds);
  }
}
