/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.format;

import org.eclipse.biscuit.crypto.PublicKey;

public class ExternalSignature {
  private final PublicKey key;
  private final byte[] signature;

  public ExternalSignature(PublicKey key, byte[] signature) {
    this.key = key;
    this.signature = signature;
  }

  public PublicKey getKey() {
    return key;
  }

  public byte[] getSignature() {
    return signature;
  }
}
