package org.eclipse.biscuit.datalog;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public final class Origin {
  private final HashSet<Long> blockIds;

  public Origin() {
    this.blockIds = new HashSet<>();
  }

  public Origin(Long i) {
    this.blockIds = new HashSet<>();
    this.blockIds.add(i);
  }

  public Origin(int i) {
    this.blockIds = new HashSet<>();
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
