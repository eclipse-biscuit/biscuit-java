package org.eclipse.biscuit.bouncycastle;

import biscuit.format.schema.Schema;
import java.security.SecureRandom;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.error.Error;

public final class DefaultKeyPairFactory implements KeyPair.Factory {
  @Override
  public KeyPair generate(Schema.PublicKey.Algorithm algorithm, byte[] bytes)
      throws Error.FormatError.InvalidKeySize {
    if (algorithm == Schema.PublicKey.Algorithm.Ed25519) {
      return new Ed25519KeyPair(bytes);
    } else if (algorithm == Schema.PublicKey.Algorithm.SECP256R1) {
      return new SECP256R1KeyPair(bytes);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }

  @Override
  public KeyPair generate(Schema.PublicKey.Algorithm algorithm, SecureRandom rng) {
    if (algorithm == Schema.PublicKey.Algorithm.Ed25519) {
      return new Ed25519KeyPair(rng);
    } else if (algorithm == Schema.PublicKey.Algorithm.SECP256R1) {
      return new SECP256R1KeyPair(rng);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }
}
