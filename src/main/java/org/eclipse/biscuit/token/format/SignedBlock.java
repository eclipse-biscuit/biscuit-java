/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.format;

import java.util.Optional;
import org.eclipse.biscuit.crypto.PublicKey;

public class SignedBlock {
  private byte[] block;
  private PublicKey key;
  private byte[] signature;
  private Optional<ExternalSignature> externalSignature;
  private int version;

  public SignedBlock(
      byte[] block,
      PublicKey key,
      byte[] signature,
      Optional<ExternalSignature> externalSignature,
      int version) {
    this.block = block;
    this.key = key;
    this.signature = signature;
    this.externalSignature = externalSignature;
    this.version = version;
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

  public Optional<ExternalSignature> getExternalSignature() {
    return externalSignature;
  }

  public int getVersion() {
    return version;
  }
}
