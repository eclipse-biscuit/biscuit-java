/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.security.SecureRandom;
import org.eclipse.biscuit.token.builder.Utils;

/** Private and public key. */
public abstract class KeyPair implements Signer {

  public static KeyPair generate(Algorithm algorithm) {
    return generate(algorithm, new SecureRandom());
  }

  public static KeyPair generate(Algorithm algorithm, String hex) {
    return generate(algorithm, Utils.hexStringToByteArray(hex));
  }

  public static KeyPair generate(Algorithm algorithm, byte[] bytes) {
    if (algorithm == Algorithm.Ed25519) {
      return new Ed25519KeyPair(bytes);
    } else if (algorithm == Algorithm.SECP256R1) {
      return new SECP256R1KeyPair(bytes);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }

  public static KeyPair generate(Algorithm algorithm, SecureRandom rng) {
    if (algorithm == Algorithm.Ed25519) {
      return new Ed25519KeyPair(rng);
    } else if (algorithm == Algorithm.SECP256R1) {
      return new SECP256R1KeyPair(rng);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }

  public abstract byte[] toBytes();

  public abstract String toHex();

  @Override
  public abstract PublicKey getPublicKey();
}
