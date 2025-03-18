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
