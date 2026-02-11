/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.security.SecureRandom;
import java.util.ServiceLoader;
import java.util.stream.Collectors;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Utils;

/** Private and public key. */
public abstract class KeyPair implements Signer {
  public interface Factory {
    KeyPair generate(Algorithm algorithm, byte[] bytes) throws Error.FormatError;

    KeyPair generate(Algorithm algorithm, SecureRandom rng) throws Error.FormatError;
  }

  private static final Factory factory;

  static {
    var factories = ServiceLoader.load(KeyPair.Factory.class).stream().collect(Collectors.toList());
    if (factories.size() != 1) {
      throw new IllegalStateException(
          "A single KeyPair implementation expected; found " + factories.size());
    }
    factory = factories.get(0).get();
  }

  public static KeyPair generate(Algorithm algorithm) throws Error.FormatError {
    return generate(algorithm, new SecureRandom());
  }

  public static KeyPair generate(Algorithm algorithm, String hex) throws Error.FormatError {
    return generate(algorithm, Utils.hexStringToByteArray(hex));
  }

  public static KeyPair generate(Algorithm algorithm, byte[] bytes) throws Error.FormatError {
    return factory.generate(algorithm, bytes);
  }

  public static KeyPair generate(Algorithm algorithm, SecureRandom rng) throws Error.FormatError {
    return factory.generate(algorithm, rng);
  }

  public abstract byte[] toBytes();

  public abstract String toHex();

  @Override
  public abstract PublicKey getPublicKey();
}
