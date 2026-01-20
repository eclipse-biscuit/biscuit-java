/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.bouncycastle;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.util.Arrays;
import java.util.Optional;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.error.Error;

class Ed25519PublicKey extends PublicKey {
  private final Ed25519PublicKeyParameters publicKey;

  Ed25519PublicKey(final Ed25519PublicKeyParameters publicKey) {
    super();
    this.publicKey = publicKey;
  }

  static Ed25519PublicKey loadEd25519(byte[] data) throws Error.FormatError.InvalidKey {
    Ed25519PublicKeyParameters params;
    try {
      params = new Ed25519PublicKeyParameters(data);
    } catch (IllegalArgumentException e) {
      throw new Error.FormatError.InvalidKey(e.getMessage());
    }
    return new Ed25519PublicKey(params);
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
  public Optional<Error> verify(byte[] data, byte[] signature) {
    if (signature.length != Ed25519KeyPair.SIGNATURE_LENGTH) {
      return Optional.of(new Error.FormatError.BlockSignatureDeserializationError(signature));
    }

    var sgr = new Ed25519Signer();
    sgr.init(false, this.publicKey);
    sgr.update(data, 0, data.length);
    if (!sgr.verifySignature(signature)) {
      return Optional.of(
          new Error.FormatError.Signature.InvalidSignature(
              "signature error: Verification equation was not satisfied"));
    }

    return Optional.empty();
  }
}
