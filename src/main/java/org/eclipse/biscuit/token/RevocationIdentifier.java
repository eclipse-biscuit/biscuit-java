/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import java.util.Base64;
import org.eclipse.biscuit.token.builder.Utils;

public final class RevocationIdentifier {
  private byte[] bytes;

  public RevocationIdentifier(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * Creates a RevocationIdentifier from base64 url (RFC4648_URLSAFE)
   *
   * @param b64url serialized revocation identifier
   * @return RevocationIdentifier
   */
  public static RevocationIdentifier fromBase64Url(String b64url) {
    return new RevocationIdentifier(Base64.getDecoder().decode(b64url));
  }

  /**
   * Serializes a revocation identifier as base64 url (RFC4648_URLSAFE)
   *
   * @return String
   */
  public String serializeBase64Url() {
    return Base64.getEncoder().encodeToString(this.bytes);
  }

  public String toHex() {
    return Utils.byteArrayToHexString(this.bytes).toLowerCase();
  }

  public static RevocationIdentifier fromBytes(byte[] bytes) {
    return new RevocationIdentifier(bytes);
  }

  public byte[] getBytes() {
    return this.bytes;
  }
}
