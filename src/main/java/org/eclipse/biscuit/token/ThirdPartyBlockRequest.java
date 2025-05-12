/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.vavr.control.Either;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Optional;
import org.eclipse.biscuit.crypto.BlockSignatureBuffer;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.crypto.Signer;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Block;

public final class ThirdPartyBlockRequest {
  private final byte[] previousSignature;

  ThirdPartyBlockRequest(byte[] previousSignature) {
    this.previousSignature = previousSignature;
  }

  public Either<Error.FormatError, ThirdPartyBlockContents> createBlock(
      final Signer externalSigner, Block blockBuilder)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    SymbolTable symbolTable = new SymbolTable();
    org.eclipse.biscuit.token.Block block =
        blockBuilder.build(symbolTable, Optional.of(externalSigner.getPublicKey()));

    Either<Error.FormatError, byte[]> res = block.toBytes();
    if (res.isLeft()) {
      return Either.left(res.getLeft());
    }

    byte[] serializedBlock = res.get();
    byte[] payload =
        BlockSignatureBuffer.generateExternalBlockSignaturePayloadV1(
            serializedBlock,
            this.previousSignature,
            BlockSignatureBuffer.THIRD_PARTY_SIGNATURE_VERSION);
    byte[] signature = externalSigner.sign(payload);

    PublicKey publicKey = externalSigner.getPublicKey();

    return Either.right(new ThirdPartyBlockContents(serializedBlock, signature, publicKey));
  }

  public Schema.ThirdPartyBlockRequest serialize() throws Error.FormatError.SerializationError {
    Schema.ThirdPartyBlockRequest.Builder b = Schema.ThirdPartyBlockRequest.newBuilder();
    b.setPreviousSignature(ByteString.copyFrom(this.previousSignature));

    return b.build();
  }

  public static ThirdPartyBlockRequest deserialize(Schema.ThirdPartyBlockRequest b)
      throws Error.FormatError.DeserializationError {

    if (b.hasLegacyPreviousKey()) {
      throw new Error.FormatError.DeserializationError(
          "public keys were provided in third-party block request");
    }
    if (b.getLegacyPublicKeysCount() > 0) {
      throw new Error.FormatError.DeserializationError(
          "public keys were provided in third-party block request");
    }

    if (!b.hasPreviousSignature()) {
      throw new Error.FormatError.DeserializationError(
          "missing previous signature in third-party block request");
    }

    return new ThirdPartyBlockRequest(b.getPreviousSignature().toByteArray());
  }

  public static ThirdPartyBlockRequest fromBytes(byte[] slice)
      throws InvalidProtocolBufferException, Error.FormatError.DeserializationError {
    return ThirdPartyBlockRequest.deserialize(Schema.ThirdPartyBlockRequest.parseFrom(slice));
  }

  public byte[] toBytes() throws IOException, Error.FormatError.SerializationError {
    Schema.ThirdPartyBlockRequest b = this.serialize();
    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    b.writeTo(stream);
    return stream.toByteArray();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    ThirdPartyBlockRequest that = (ThirdPartyBlockRequest) o;

    return Arrays.equals(previousSignature, that.previousSignature);
  }

  @Override
  public int hashCode() {
    return previousSignature != null ? Arrays.hashCode(previousSignature) : 0;
  }

  @Override
  public String toString() {
    return "ThirdPartyBlockRequest{previousSignature=" + previousSignature + '}';
  }
}
