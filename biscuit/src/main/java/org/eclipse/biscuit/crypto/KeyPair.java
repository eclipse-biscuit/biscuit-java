/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.security.SecureRandom;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Utils;

/** Private and public key. */
public abstract class KeyPair implements Signer {
  public interface Factory {
    KeyPair generate(byte[] bytes) throws Error.FormatError.InvalidKeySize;

    KeyPair generate(SecureRandom rng);
  }

  public static final Factory DEFAULT_ED25519_FACTORY =
      new Factory() {
        @Override
        public KeyPair generate(byte[] bytes) throws Error.FormatError.InvalidKeySize {
          return new Ed25519KeyPair(bytes);
        }

        @Override
        public KeyPair generate(SecureRandom rng) {
          return new Ed25519KeyPair(rng);
        }
      };

  public static final Factory DEFAULT_SECP256R1_FACTORY =
      new Factory() {
        @Override
        public KeyPair generate(byte[] bytes) throws Error.FormatError.InvalidKeySize {
          return new SECP256R1KeyPair(bytes, true);
        }

        @Override
        public KeyPair generate(SecureRandom rng) {
          return new SECP256R1KeyPair(rng, true);
        }
      };

  public static final Factory DEFAULT_NONDETERMINISTIC_SECP256R1_FACTORY =
      new Factory() {
        @Override
        public KeyPair generate(byte[] bytes) throws Error.FormatError.InvalidKeySize {
          return new SECP256R1KeyPair(bytes, false);
        }

        @Override
        public KeyPair generate(SecureRandom rng) {
          return new SECP256R1KeyPair(rng, false);
        }
      };

  private static volatile Factory ed25519Factory = DEFAULT_ED25519_FACTORY;
  private static volatile Factory secp256r1Factory = DEFAULT_SECP256R1_FACTORY;

  public static KeyPair generate(Algorithm algorithm) {
    return generate(algorithm, new SecureRandom());
  }

  public static KeyPair generate(Algorithm algorithm, String hex)
      throws Error.FormatError.InvalidKeySize {
    return generate(algorithm, Utils.hexStringToByteArray(hex));
  }

  public static KeyPair generate(Algorithm algorithm, byte[] bytes)
      throws Error.FormatError.InvalidKeySize {
    if (algorithm == Algorithm.Ed25519) {
      return ed25519Factory.generate(bytes);
    } else if (algorithm == Algorithm.SECP256R1) {
      return secp256r1Factory.generate(bytes);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }

  public static KeyPair generate(Algorithm algorithm, SecureRandom rng) {
    if (algorithm == Algorithm.Ed25519) {
      return ed25519Factory.generate(rng);
    } else if (algorithm == Algorithm.SECP256R1) {
      return secp256r1Factory.generate(rng);
    } else {
      throw new IllegalArgumentException("Unsupported algorithm");
    }
  }

  public static void setEd25519Factory(Factory factory) {
    ed25519Factory = factory;
  }

  public static void setSECP256R1Factory(Factory factory) {
    secp256r1Factory = factory;
  }

  public abstract byte[] toBytes();

  public abstract String toHex();

  @Override
  public abstract PublicKey getPublicKey();
}
