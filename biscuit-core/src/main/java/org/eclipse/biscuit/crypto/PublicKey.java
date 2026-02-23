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
import java.util.ServiceLoader;
import java.util.Set;
import java.util.stream.Collectors;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Utils;

public abstract class PublicKey {
  public interface Factory {
    PublicKey load(Algorithm algorithm, byte[] bytes) throws Error.FormatError;
  }

  private static final Factory factory;

  static {
    var factories =
        ServiceLoader.load(PublicKey.Factory.class).stream().collect(Collectors.toList());
    if (factories.size() != 1) {
      throw new IllegalStateException(
          "A single PublicKey implementation expected; found " + factories.size());
    }
    factory = factories.get(0).get();
  }

  private static final Set<Algorithm> SUPPORTED_ALGORITHMS =
      Set.of(Algorithm.Ed25519, Algorithm.SECP256R1);

  public static PublicKey load(Algorithm algorithm, byte[] data) throws Error.FormatError {
    return factory.load(algorithm, data);
  }

  public static PublicKey load(Algorithm algorithm, String hex) throws Error.FormatError {
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

  public static PublicKey deserialize(Schema.PublicKey pk) throws Error.FormatError {
    if (!pk.hasAlgorithm() || !pk.hasKey() || !SUPPORTED_ALGORITHMS.contains(pk.getAlgorithm())) {
      throw new Error.FormatError.DeserializationError("Invalid public key");
    }
    return PublicKey.load(pk.getAlgorithm(), pk.getKey().toByteArray());
  }

  public abstract Algorithm getAlgorithm();

  public abstract Optional<Error> verify(byte[] data, byte[] signature)
      throws InvalidKeyException, SignatureException, NoSuchAlgorithmException;
}
