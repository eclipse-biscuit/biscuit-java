/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import static org.eclipse.biscuit.crypto.SECP256R1KeyPair.CURVE;
import static org.eclipse.biscuit.crypto.SECP256R1KeyPair.getSignature;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
class SECP256R1PublicKey extends PublicKey {

  private final BCECPublicKey publicKey;

  SECP256R1PublicKey(BCECPublicKey publicKey) {
    super();
    this.publicKey = publicKey;
  }

  static SECP256R1PublicKey loadSECP256R1(byte[] data) {
    var params = ECNamedCurveTable.getParameterSpec(CURVE);
    var spec = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
    return new SECP256R1PublicKey(
        new BCECPublicKey(SECP256R1KeyPair.ALGORITHM, spec, BouncyCastleProvider.CONFIGURATION));
  }

  @Override
  public byte[] toBytes() {
    return this.publicKey.getQ().getEncoded(true);
  } // true : compressed

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    SECP256R1PublicKey publicKey = (SECP256R1PublicKey) o;

    return Arrays.equals(this.toBytes(), publicKey.toBytes());
  }

  @Override
  public int hashCode() {
    return this.publicKey.hashCode();
  }

  @Override
  public String toString() {
    return "secp256r1/" + toHex().toLowerCase();
  }

  public Algorithm getAlgorithm() {
    return Algorithm.SECP256R1;
  }

  @Override
  public boolean verify(byte[] data, byte[] signature)
      throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
    var sgr = getSignature();
    sgr.initVerify(this.publicKey);
    sgr.update(data);
    return sgr.verify(signature);
  }
}
