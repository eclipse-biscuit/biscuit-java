/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import static org.eclipse.biscuit.crypto.SECP256R1KeyPair.CURVE;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.eclipse.biscuit.error.Error;

@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
class SECP256R1PublicKey extends PublicKey {

  private static final X9ECParameters x9ECParameters = SECNamedCurves.getByName("secp256r1");
  private static final ECDomainParameters domainParameters =
      new ECDomainParameters(
          x9ECParameters.getCurve(),
          x9ECParameters.getG(),
          x9ECParameters.getN(),
          x9ECParameters.getH());

  private final BCECPublicKey publicKey;

  SECP256R1PublicKey(BCECPublicKey publicKey) {
    super();
    this.publicKey = publicKey;
  }

  static SECP256R1PublicKey loadSECP256R1(byte[] data) throws Error.FormatError.InvalidKey {
    var params = ECNamedCurveTable.getParameterSpec(CURVE);
    ECPoint ecPoint;
    try {
      ecPoint = params.getCurve().decodePoint(data);
    } catch (IllegalArgumentException e) {
      throw new Error.FormatError.InvalidKey(e.getMessage());
    }
    var spec = new ECPublicKeySpec(ecPoint, params);
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
  public Optional<Error> verify(byte[] data, byte[] signature) {
    if (signature.length < SECP256R1KeyPair.MINIMUM_SIGNATURE_LENGTH
        || signature.length > SECP256R1KeyPair.MAXIMUM_SIGNATURE_LENGTH) {
      return Optional.of(new Error.FormatError.BlockSignatureDeserializationError(signature));
    }

    var digest = new SHA256Digest();
    digest.update(data, 0, data.length);
    var hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    var signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    signer.init(false, new ECPublicKeyParameters(publicKey.getQ(), domainParameters));

    BigInteger[] sig;
    try {
      sig = StandardDSAEncoding.INSTANCE.decode(signer.getOrder(), signature);
    } catch (IOException e) {
      throw new IllegalStateException(e.toString());
    }

    if (!signer.verifySignature(hash, sig[0], sig[1])) {
      return Optional.of(
          new Error.FormatError.Signature.InvalidSignature(
              "signature error: Verification equation was not satisfied"));
    }

    return Optional.empty();
  }
}
