package org.eclipse.biscuit.token.format;

import org.eclipse.biscuit.crypto.PublicKey;

public class ExternalSignature {
  private final PublicKey key;
  private final byte[] signature;

  public ExternalSignature(PublicKey key, byte[] signature) {
    this.key = key;
    this.signature = signature;
  }

  public PublicKey getKey() {
    return key;
  }

  public byte[] getSignature() {
    return signature;
  }
}
