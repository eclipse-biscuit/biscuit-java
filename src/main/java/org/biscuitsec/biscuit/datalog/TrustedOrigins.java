package org.biscuitsec.biscuit.datalog;

import java.util.HashMap;
import java.util.List;

public final class TrustedOrigins {
  private final Origin origin;

  public TrustedOrigins(int... origins) {
    Origin origin = new Origin();
    for (int i : origins) {
      origin.add(i);
    }
    this.origin = origin;
  }

  private TrustedOrigins() {
    origin = new Origin();
  }

  private TrustedOrigins(Origin inner) {
    if (inner == null) {
      throw new RuntimeException();
    }
    this.origin = inner;
  }

  public TrustedOrigins clone() {
    return new TrustedOrigins(this.origin.clone());
  }

  public static TrustedOrigins defaultOrigins() {
    TrustedOrigins origins = new TrustedOrigins();
    origins.origin.add(0);
    origins.origin.add(Long.MAX_VALUE);
    return origins;
  }

  public static TrustedOrigins fromScopes(
      List<Scope> ruleScopes,
      TrustedOrigins defaultOrigins,
      long currentBlock,
      HashMap<Long, List<Long>> publicKeyToBlockId) {
    if (ruleScopes.isEmpty()) {
      TrustedOrigins origins = defaultOrigins.clone();
      origins.origin.add(currentBlock);
      origins.origin.add(Long.MAX_VALUE);
      return origins;
    }

    TrustedOrigins origins = new TrustedOrigins();
    origins.origin.add(currentBlock);
    origins.origin.add(Long.MAX_VALUE);

    for (Scope scope : ruleScopes) {
      switch (scope.kind()) {
        case Authority:
          origins.origin.add(0);
          break;
        case Previous:
          if (currentBlock != Long.MAX_VALUE) {
            for (long i = 0; i < currentBlock + 1; i++) {
              origins.origin.add(i);
            }
          }
          break;
        case PublicKey:
          List<Long> blockIds = publicKeyToBlockId.get(scope.publicKey());
          if (blockIds != null) {
            origins.origin.addAll(blockIds);
          }
          break;
        default:
      }
    }

    return origins;
  }

  public boolean contains(Origin factOrigin) {
    return this.origin.containsAll(factOrigin);
  }

  @Override
  public String toString() {
    return "TrustedOrigins{inner=" + origin + '}';
  }

  public Origin getOrigin() {
    return origin;
  }
}
