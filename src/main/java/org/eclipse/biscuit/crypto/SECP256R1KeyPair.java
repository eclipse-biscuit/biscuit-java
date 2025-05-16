/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import org.eclipse.biscuit.token.builder.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.BigIntegers;

@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
final class SECP256R1KeyPair extends KeyPair {

  static final int MINIMUM_SIGNATURE_LENGTH = 68;
  static final int MAXIMUM_SIGNATURE_LENGTH = 72;
  private static final int BUFFER_SIZE = 32;

  private final BCECPrivateKey privateKey;
  private final BCECPublicKey publicKey;

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  static final String ALGORITHM = "ECDSA";
  static final String CURVE = "secp256r1";
  static final ECNamedCurveParameterSpec SECP256R1 = ECNamedCurveTable.getParameterSpec(CURVE);

  SECP256R1KeyPair(byte[] bytes) {
    var privateKeySpec = new ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(bytes), SECP256R1);
    var privateKey =
        new BCECPrivateKey(ALGORITHM, privateKeySpec, BouncyCastleProvider.CONFIGURATION);

    var publicKeySpec =
        new ECPublicKeySpec(SECP256R1.getG().multiply(privateKeySpec.getD()), SECP256R1);
    var publicKey = new BCECPublicKey(ALGORITHM, publicKeySpec, BouncyCastleProvider.CONFIGURATION);

    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  SECP256R1KeyPair(SecureRandom rng) {
    byte[] bytes = new byte[BUFFER_SIZE];
    rng.nextBytes(bytes);

    var privateKeySpec = new ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(bytes), SECP256R1);
    var privateKey =
        new BCECPrivateKey(ALGORITHM, privateKeySpec, BouncyCastleProvider.CONFIGURATION);

    var publicKeySpec =
        new ECPublicKeySpec(SECP256R1.getG().multiply(privateKeySpec.getD()), SECP256R1);
    var publicKey = new BCECPublicKey(ALGORITHM, publicKeySpec, BouncyCastleProvider.CONFIGURATION);

    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static Signature getSignature() throws NoSuchAlgorithmException {
    return Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
  }

  @Override
  public byte[] sign(byte[] data)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature sgr = getSignature();
    sgr.initSign(privateKey);
    sgr.update(data);
    return sgr.sign();
  }

  @Override
  public byte[] toBytes() {
    return BigIntegers.asUnsignedByteArray(privateKey.getD());
  }

  @Override
  public String toHex() {
    return Utils.byteArrayToHexString(toBytes());
  }

  @Override
  public PublicKey getPublicKey() {
    return new SECP256R1PublicKey(this.publicKey);
  }
}
