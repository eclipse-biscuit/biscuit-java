/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema;
import biscuit.format.schema.Schema.PublicKey.Algorithm;
import com.google.protobuf.ByteString;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Optional;
import java.util.Set;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Utils;

public abstract class PublicKey {

  private static final Set<Algorithm> SUPPORTED_ALGORITHMS =
      Set.of(Algorithm.Ed25519, Algorithm.SECP256R1);

  public static PublicKey load(Algorithm algorithm, byte[] data) {
    if (algorithm == Algorithm.Ed25519) {
      return Ed25519PublicKey.loadEd25519(data);
    } else if (algorithm == Algorithm.SECP256R1) {
      return SECP256R1PublicKey.loadSECP256R1(data);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }

  public static PublicKey load(Algorithm algorithm, String hex) {
    return load(algorithm, Utils.hexStringToByteArray(hex));
  }

  public abstract byte[] toBytes();

  public String toHex() {
    return Utils.byteArrayToHexString(this.toBytes());
  }

  public Schema.PublicKey serialize() {
    Schema.PublicKey.Builder publicKey = Schema.PublicKey.newBuilder();
    publicKey.setKey(ByteString.copyFrom(this.toBytes()));
    publicKey.setAlgorithm(this.getAlgorithm());
    return publicKey.build();
  }

  public static PublicKey deserialize(Schema.PublicKey pk)
      throws Error.FormatError.DeserializationError {
    if (!pk.hasAlgorithm() || !pk.hasKey() || !SUPPORTED_ALGORITHMS.contains(pk.getAlgorithm())) {
      throw new Error.FormatError.DeserializationError("Invalid public key");
    }
    return PublicKey.load(pk.getAlgorithm(), pk.getKey().toByteArray());
  }

  public static Optional<Error> validateSignatureLength(Algorithm algorithm, int length) {
    Optional<Error> error = Optional.empty();
    if (algorithm == Algorithm.Ed25519) {
      if (length != Ed25519KeyPair.SIGNATURE_LENGTH) {
        error = Optional.of(new Error.FormatError.Signature.InvalidSignatureSize(length));
      }
    } else if (algorithm == Algorithm.SECP256R1) {
      if (length < SECP256R1KeyPair.MINIMUM_SIGNATURE_LENGTH
          || length > SECP256R1KeyPair.MAXIMUM_SIGNATURE_LENGTH) {
        error = Optional.of(new Error.FormatError.Signature.InvalidSignatureSize(length));
      }
    } else {
      error =
          Optional.of(new Error.FormatError.Signature.InvalidSignature("unsupported algorithm"));
    }
    return error;
  }

  public abstract Algorithm getAlgorithm();

  public abstract boolean verify(byte[] data, byte[] signature)
      throws InvalidKeyException, SignatureException, NoSuchAlgorithmException;
}
