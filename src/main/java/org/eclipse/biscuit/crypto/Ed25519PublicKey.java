/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.util.Arrays;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

class Ed25519PublicKey extends PublicKey {
  private final Ed25519PublicKeyParameters publicKey;

  Ed25519PublicKey(final Ed25519PublicKeyParameters publicKey) {
    super();
    this.publicKey = publicKey;
  }

  static Ed25519PublicKey loadEd25519(byte[] data) {
    return new Ed25519PublicKey(new Ed25519PublicKeyParameters(data));
  }

  @Override
  public byte[] toBytes() {
    return this.publicKey.getEncoded();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Ed25519PublicKey publicKey = (Ed25519PublicKey) o;

    return Arrays.equals(this.toBytes(), publicKey.toBytes());
  }

  @Override
  public int hashCode() {
    return this.publicKey.hashCode();
  }

  @Override
  public String toString() {
    return "ed25519/" + toHex().toLowerCase();
  }

  public Algorithm getAlgorithm() {
    return Algorithm.Ed25519;
  }

  @Override
  public boolean verify(byte[] data, byte[] signature) {
    var sgr = new Ed25519Signer();
    sgr.init(false, this.publicKey);
    sgr.update(data, 0, data.length);
    return sgr.verifySignature(signature);
  }
}
