/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import biscuit.format.schema.Schema;
import com.google.protobuf.InvalidProtocolBufferException;
import io.vavr.control.Either;
import io.vavr.control.Option;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Objects;
import org.eclipse.biscuit.crypto.BlockSignatureBuffer;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.crypto.Signer;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Block;

public final class ThirdPartyBlockRequest {
  private final PublicKey previousKey;

  ThirdPartyBlockRequest(PublicKey previousKey) {
    this.previousKey = previousKey;
  }

  public Either<Error.FormatError, ThirdPartyBlockContents> createBlock(
      final Signer externalSigner, Block blockBuilder)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    SymbolTable symbolTable = new SymbolTable();
    org.eclipse.biscuit.token.Block block =
        blockBuilder.build(symbolTable, Option.some(externalSigner.getPublicKey()));

    Either<Error.FormatError, byte[]> res = block.toBytes();
    if (res.isLeft()) {
      return Either.left(res.getLeft());
    }

    byte[] serializedBlock = res.get();
    byte[] payload =
        BlockSignatureBuffer.generateExternalBlockSignaturePayloadV0(
            serializedBlock, this.previousKey);
    byte[] signature = externalSigner.sign(payload);

    PublicKey publicKey = externalSigner.getPublicKey();

    return Either.right(new ThirdPartyBlockContents(serializedBlock, signature, publicKey));
  }

  public Schema.ThirdPartyBlockRequest serialize() throws Error.FormatError.SerializationError {
    Schema.ThirdPartyBlockRequest.Builder b = Schema.ThirdPartyBlockRequest.newBuilder();
    b.setPreviousKey(this.previousKey.serialize());

    return b.build();
  }

  public static ThirdPartyBlockRequest deserialize(Schema.ThirdPartyBlockRequest b)
      throws Error.FormatError.DeserializationError {
    PublicKey previousKey = PublicKey.deserialize(b.getPreviousKey());
    return new ThirdPartyBlockRequest(previousKey);
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

    return Objects.equals(previousKey, that.previousKey);
  }

  @Override
  public int hashCode() {
    return previousKey != null ? previousKey.hashCode() : 0;
  }

  @Override
  public String toString() {
    return "ThirdPartyBlockRequest{previousKey=" + previousKey + '}';
  }
}
