/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.BigIntegers;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Utils;

@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
final class SECP256R1KeyPair extends KeyPair {

  static final int MINIMUM_SIGNATURE_LENGTH = 68;
  static final int MAXIMUM_SIGNATURE_LENGTH = 72;
  private static final int BUFFER_SIZE = 32;

  private final BCECPrivateKey privateKey;
  private final BCECPublicKey publicKey;

  static final String ALGORITHM = "ECDSA";
  static final String CURVE = "secp256r1";
  static final ECNamedCurveParameterSpec SECP256R1 = ECNamedCurveTable.getParameterSpec(CURVE);

  SECP256R1KeyPair(byte[] bytes) throws Error.FormatError.InvalidKeySize {
    if (bytes.length != BUFFER_SIZE) {
      throw new Error.FormatError.InvalidKeySize(bytes.length);
    }
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

  @Override
  public byte[] sign(byte[] data) {
    var digest = new SHA256Digest();
    digest.update(data, 0, data.length);
    var hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    var signer = new ECDSASigner();
    signer.init(true, privateKey.engineGetKeyParameters());
    var sig = signer.generateSignature(hash);

    try {
      return StandardDSAEncoding.INSTANCE.encode(signer.getOrder(), sig[0], sig[1]);
    } catch (IOException e) {
      throw new IllegalStateException(e.toString());
    }
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
