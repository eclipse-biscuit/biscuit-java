/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import java.security.SecureRandom;
import org.eclipse.biscuit.token.builder.Utils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

final class Ed25519KeyPair extends KeyPair {
  public static final int SIGNATURE_LENGTH = 64;

  private final Ed25519PrivateKeyParameters privateKey;
  private final Ed25519PublicKeyParameters publicKey;

  Ed25519KeyPair(byte[] bytes) {
    Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(bytes);
    Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();

    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  Ed25519KeyPair(SecureRandom rng) {

    Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
    kpg.init(new Ed25519KeyGenerationParameters(rng));

    AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
    Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) kp.getPrivate();
    Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) kp.getPublic();

    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  @Override
  public byte[] sign(byte[] data) {
    var sgr = new Ed25519Signer();
    sgr.init(true, this.privateKey);
    sgr.update(data, 0, data.length);
    return sgr.generateSignature();
  }

  @Override
  public byte[] toBytes() {
    return privateKey.getEncoded();
  }

  @Override
  public String toHex() {
    return Utils.byteArrayToHexString(toBytes());
  }

  @Override
  public PublicKey getPublicKey() {
    return new Ed25519PublicKey(this.publicKey);
  }
}
