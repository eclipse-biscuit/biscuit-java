/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

import io.vavr.control.Either;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Optional;
import org.eclipse.biscuit.error.Error;

class Token {
  private final ArrayList<byte[]> blocks;
  private final ArrayList<PublicKey> keys;
  private final ArrayList<byte[]> signatures;
  private final KeyPair next;

  Token(final Signer rootSigner, byte[] message, KeyPair next)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

    this.blocks = new ArrayList<>();
    this.blocks.add(message);
    this.keys = new ArrayList<>();
    this.keys.add(next.getPublicKey());
    this.signatures = new ArrayList<>();
    byte[] payload =
        BlockSignatureBuffer.generateBlockSignaturePayloadV0(
            message, next.getPublicKey(), Optional.empty());
    byte[] signature = rootSigner.sign(payload);
    this.signatures.add(signature);
    this.next = next;
  }

  Token(
      final ArrayList<byte[]> blocks,
      final ArrayList<PublicKey> keys,
      final ArrayList<byte[]> signatures,
      final KeyPair next) {
    this.signatures = signatures;
    this.blocks = blocks;
    this.keys = keys;
    this.next = next;
  }

  Token append(KeyPair keyPair, byte[] message)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    byte[] payload =
        BlockSignatureBuffer.generateBlockSignaturePayloadV0(
            message, keyPair.getPublicKey(), Optional.empty());
    byte[] signature = this.next.sign(payload);

    Token token = new Token(this.blocks, this.keys, this.signatures, keyPair);
    token.blocks.add(message);
    token.signatures.add(signature);
    token.keys.add(keyPair.getPublicKey());

    return token;
  }

  // FIXME: rust version returns a Result<(), error::Signature>
  public Either<Error, Void> verify(PublicKey root)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    PublicKey currentKey = root;
    for (int i = 0; i < this.blocks.size(); i++) {
      byte[] block = this.blocks.get(i);
      PublicKey nextKey = this.keys.get(i);
      byte[] signature = this.signatures.get(i);

      byte[] payload =
          BlockSignatureBuffer.generateBlockSignaturePayloadV0(block, nextKey, Optional.empty());
      if (currentKey.verify(payload, signature)) {
        currentKey = nextKey;
      } else {
        return Left(
            new Error.FormatError.Signature.InvalidSignature(
                "signature error: Verification equation was not satisfied"));
      }
    }

    if (this.next.getPublicKey().equals(currentKey)) {
      return Right(null);
    } else {
      return Left(
          new Error.FormatError.Signature.InvalidSignature(
              "signature error: Verification equation was not satisfied"));
    }
  }
}
