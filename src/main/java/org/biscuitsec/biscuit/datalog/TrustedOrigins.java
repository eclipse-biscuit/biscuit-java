package org.biscuitsec.biscuit.datalog;

import java.util.HashMap;
import java.util.List;

public final class TrustedOrigins {
    private final Origin inner;

    public TrustedOrigins(int... origins) {
        Origin origin = new Origin();
        for (int i : origins) {
            origin.add(i);
        }
        inner = origin;
    }

    private TrustedOrigins() {
        inner = new Origin();
    }

    private TrustedOrigins(Origin inner) {
        if (inner == null) {
            throw new RuntimeException();
        }
        this.inner = inner;
    }

    public TrustedOrigins clone() {
        return new TrustedOrigins(this.inner.clone());
    }

    public static TrustedOrigins defaultOrigins() {
        TrustedOrigins origins = new TrustedOrigins();
        origins.inner.add(0);
        origins.inner.add(Long.MAX_VALUE);
        return origins;
    }

    public static TrustedOrigins fromScopes(List<Scope> ruleScopes,
                                            TrustedOrigins defaultOrigins,
                                            long currentBlock,
                                            HashMap<Long, List<Long>> publicKeyToBlockId) {
        if (ruleScopes.isEmpty()) {
            TrustedOrigins origins = defaultOrigins.clone();
            origins.inner.add(currentBlock);
            origins.inner.add(Long.MAX_VALUE);
            return origins;
        }

        TrustedOrigins origins = new TrustedOrigins();
        origins.inner.add(currentBlock);
        origins.inner.add(Long.MAX_VALUE);

        for (Scope scope : ruleScopes) {
            switch (scope.kind()) {
                case Authority:
                    origins.inner.add(0);
                    break;
                case Previous:
                    if (currentBlock != Long.MAX_VALUE) {
                        for (long i = 0; i < currentBlock + 1; i++) {
                            origins.inner.add(i);
                        }
                    }
                    break;
                case PublicKey:
                    List<Long> blockIds = publicKeyToBlockId.get(scope.publicKey());
                    if (blockIds != null) {
                        origins.inner.inner.addAll(blockIds);
                    }
            }
        }

        return origins;
    }

    public boolean contains(Origin factOrigin) {
        return this.inner.inner.containsAll(factOrigin.inner);
    }

    @Override
    public String toString() {
        return "TrustedOrigins{" +
                "inner=" + inner +
                '}';
    }
}
