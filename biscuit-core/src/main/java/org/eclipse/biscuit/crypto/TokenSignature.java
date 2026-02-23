/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import org.eclipse.biscuit.token.builder.Utils;

/** Signature aggregation */
public final class TokenSignature {
  private TokenSignature() {}

  public static String hex(byte[] byteArray) {
    StringBuilder result = new StringBuilder();
    for (byte bb : byteArray) {
      result.append(String.format("%02X", bb));
    }
    return result.toString();
  }

  public static byte[] fromHex(String s) {
    return Utils.hexStringToByteArray(s);
  }
}
