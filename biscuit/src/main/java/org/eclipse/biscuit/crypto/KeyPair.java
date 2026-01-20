/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.security.SecureRandom;
import org.eclipse.biscuit.bouncycastle.DefaultKeyPairFactory;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Utils;

/** Private and public key. */
public abstract class KeyPair implements Signer {
  public interface Factory {
    KeyPair generate(Algorithm algorithm, byte[] bytes) throws Error.FormatError.InvalidKeySize;

    KeyPair generate(Algorithm algorithm, SecureRandom rng);
  }

  private static volatile Factory factory = new DefaultKeyPairFactory();

  public static KeyPair generate(Algorithm algorithm) {
    return generate(algorithm, new SecureRandom());
  }

  public static KeyPair generate(Algorithm algorithm, String hex)
      throws Error.FormatError.InvalidKeySize {
    return generate(algorithm, Utils.hexStringToByteArray(hex));
  }

  public static KeyPair generate(Algorithm algorithm, byte[] bytes)
      throws Error.FormatError.InvalidKeySize {
    return factory.generate(algorithm, bytes);
  }

  public static KeyPair generate(Algorithm algorithm, SecureRandom rng) {
    return factory.generate(algorithm, rng);
  }

  public static void setFactory(Factory factory) {
    KeyPair.factory = factory;
  }

  public abstract byte[] toBytes();

  public abstract String toHex();

  @Override
  public abstract PublicKey getPublicKey();
}
