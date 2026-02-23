/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.format;

import java.util.Optional;
import org.eclipse.biscuit.crypto.KeyPair;

/** Sum type for Proof NextSecret or FinalSignature. */
interface Proof {
  /**
   * Test if the proof is sealed.
   *
   * @return true if sealed and is FinalSignature
   */
  boolean isSealed();

  /**
   * Get the KeyPair of the proof if the proof is not sealed.
   *
   * @return secret keypair if not sealed
   */
  KeyPair secretKey();

  /**
   * Get the signature in case of sealed proof.
   *
   * @return the signature if sealed or none
   */
  Optional<byte[]> getSignature();

  /** NextSecret with a keypair. */
  final class NextSecret implements Proof {
    /** the secret keypair for the block. */
    private final KeyPair secretKey;

    /**
     * Create a new NextSecret.
     *
     * @param secretKey the associated keypair
     */
    NextSecret(final KeyPair secretKey) {
      this.secretKey = secretKey;
    }

    @Override
    public KeyPair secretKey() {
      return this.secretKey;
    }

    @Override
    public boolean isSealed() {
      return false;
    }

    @Override
    public Optional<byte[]> getSignature() {
      return Optional.empty();
    }
  }

  final class FinalSignature implements Proof {
    /** final signature. */
    private final byte[] signature;

    FinalSignature(final byte[] signature) {
      this.signature = signature;
    }

    public byte[] signature() {
      return this.signature;
    }

    @Override
    public KeyPair secretKey() {
      throw new RuntimeException("Sealed Block no keypair available");
    }

    @Override
    public boolean isSealed() {
      return true;
    }

    @Override
    public Optional<byte[]> getSignature() {
      return Optional.of(this.signature);
    }
  }
}
