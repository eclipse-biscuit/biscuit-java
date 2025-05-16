/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.format;

import io.vavr.control.Option;
import org.eclipse.biscuit.crypto.PublicKey;

public class SignedBlock {
  private byte[] block;
  private PublicKey key;
  private byte[] signature;
  private Option<ExternalSignature> externalSignature;

  public SignedBlock(
      byte[] block, PublicKey key, byte[] signature, Option<ExternalSignature> externalSignature) {
    this.block = block;
    this.key = key;
    this.signature = signature;
    this.externalSignature = externalSignature;
  }

  public byte[] getBlock() {
    return block;
  }

  public PublicKey getKey() {
    return key;
  }

  public byte[] getSignature() {
    return signature;
  }

  public Option<ExternalSignature> getExternalSignature() {
    return externalSignature;
  }
}
