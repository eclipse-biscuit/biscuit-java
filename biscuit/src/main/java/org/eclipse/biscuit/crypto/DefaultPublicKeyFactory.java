package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema;
import org.eclipse.biscuit.error.Error;

public final class DefaultPublicKeyFactory implements PublicKey.Factory {
  @Override
  public PublicKey load(Schema.PublicKey.Algorithm algorithm, byte[] bytes)
      throws Error.FormatError.InvalidKey {
    if (algorithm == Schema.PublicKey.Algorithm.Ed25519) {
      return Ed25519PublicKey.loadEd25519(bytes);
    } else if (algorithm == Schema.PublicKey.Algorithm.SECP256R1) {
      return SECP256R1PublicKey.loadSECP256R1(bytes);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }
}
