/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import biscuit.format.schema.Schema;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.stream.Stream;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.format.ExternalSignature;
import org.eclipse.biscuit.token.format.SerializedBiscuit;
import org.eclipse.biscuit.token.format.SignedBlock;

public final class BlockSignatureBuffer {
  public static final int THIRD_PARTY_SIGNATURE_VERSION = 1;
  public static final int DATALOG_3_3_SIGNATURE_VERSION = 1;
  public static final int NON_ED25519_SIGNATURE_VERSION = 1;

  private static final byte[] BLOCK_VERSION =
      "\0BLOCK\0\0VERSION\0".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] EXTERNAL_VERSION =
      "\0EXTERNAL\0\0VERSION\0".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] PAYLOAD = "\0PAYLOAD\0".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] ALGORITHM = "\0ALGORITHM\0".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] NEXTKEY = "\0NEXTKEY\0".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] PREVSIG = "\0PREVSIG\0".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] EXTERNALSIG = "\0EXTERNALSIG\0".getBytes(StandardCharsets.US_ASCII);

  private BlockSignatureBuffer() {}

  public static int blockSignatureVersion(
      PublicKey blockKey,
      PublicKey nextKey,
      Optional<ExternalSignature> externalSignature,
      Optional<Long> blockVersion,
      Stream<Integer> previousSigVersions) {
    if (externalSignature.isPresent()) {
      return THIRD_PARTY_SIGNATURE_VERSION;
    }

    if (blockVersion.isPresent() && blockVersion.get() >= SerializedBiscuit.DATALOG_3_3) {
      return DATALOG_3_3_SIGNATURE_VERSION;
    }

    if (blockKey.getAlgorithm() != Schema.PublicKey.Algorithm.Ed25519
        || nextKey.getAlgorithm() != Schema.PublicKey.Algorithm.Ed25519) {
      return NON_ED25519_SIGNATURE_VERSION;
    }

    return previousSigVersions.mapToInt(Integer::intValue).max().orElse(0);
  }

  public static Result<byte[], Error.FormatError> generateBlockSignaturePayload(
      byte[] payload,
      PublicKey nextKey,
      Optional<ExternalSignature> externalSignature,
      Optional<byte[]> previousSignature,
      int version) {
    switch (version) {
      case 0:
        return Result.ok(generateBlockSignaturePayloadV0(payload, nextKey, externalSignature));
      case 1:
        return Result.ok(
            generateBlockSignaturePayloadV1(
                payload, nextKey, externalSignature, previousSignature, version));
      default:
        return Result.err(
            new Error.FormatError.DeserializationError("unsupported block version " + version));
    }
  }

  public static byte[] generateBlockSignaturePayloadV0(
      byte[] payload, PublicKey nextKey, Optional<ExternalSignature> externalSignature) {
    var nextKeyBytes = nextKey.toBytes();
    var capacity = payload.length + Integer.BYTES + nextKeyBytes.length;
    if (externalSignature.isPresent()) {
      capacity += externalSignature.get().getSignature().length;
    }
    var toVerify = ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
    toVerify.put(payload);
    if (externalSignature.isPresent()) {
      toVerify.put(externalSignature.get().getSignature());
    }
    toVerify.putInt(nextKey.getAlgorithm().getNumber());
    toVerify.put(nextKeyBytes);
    toVerify.flip();
    return toVerify.array();
  }

  public static byte[] generateBlockSignaturePayloadV1(
      byte[] payload,
      PublicKey nextKey,
      Optional<ExternalSignature> externalSignature,
      Optional<byte[]> previousSignature,
      int version) {
    var nextKeyBytes = nextKey.toBytes();
    var capacity =
        BLOCK_VERSION.length
            + Integer.BYTES
            + PAYLOAD.length
            + payload.length
            + ALGORITHM.length
            + Integer.BYTES
            + NEXTKEY.length
            + nextKeyBytes.length;
    if (previousSignature.isPresent()) {
      capacity += PREVSIG.length + previousSignature.get().length;
    }
    if (externalSignature.isPresent()) {
      capacity += EXTERNALSIG.length + externalSignature.get().getSignature().length;
    }

    var toVerify = ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
    toVerify.put(BLOCK_VERSION);
    toVerify.putInt(version);
    toVerify.put(PAYLOAD);
    toVerify.put(payload);
    toVerify.put(ALGORITHM);
    toVerify.putInt(nextKey.getAlgorithm().getNumber());
    toVerify.put(NEXTKEY);
    toVerify.put(nextKeyBytes);
    if (previousSignature.isPresent()) {
      toVerify.put(PREVSIG);
      toVerify.put(previousSignature.get());
    }
    if (externalSignature.isPresent()) {
      toVerify.put(EXTERNALSIG);
      toVerify.put(externalSignature.get().getSignature());
    }
    toVerify.flip();
    return toVerify.array();
  }

  public static byte[] generateExternalBlockSignaturePayload(
      byte[] payload, PublicKey previousKey, byte[] previousSignature, int version) {
    if (version == 0) {
      return generateExternalBlockSignaturePayloadV0(payload, previousKey);
    } else {
      return generateExternalBlockSignaturePayloadV1(payload, previousSignature, version);
    }
  }

  public static byte[] generateExternalBlockSignaturePayloadV0(
      byte[] payload, PublicKey previousKey) {
    var previousKeyBytes = previousKey.toBytes();
    var capacity = payload.length + Integer.BYTES + previousKeyBytes.length;
    var toVerify = ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
    toVerify.put(payload);
    toVerify.putInt(previousKey.getAlgorithm().getNumber());
    toVerify.put(previousKey.toBytes());
    toVerify.flip();
    return toVerify.array();
  }

  public static byte[] generateExternalBlockSignaturePayloadV1(
      byte[] payload, byte[] previousSignature, int version) {
    var capacity =
        EXTERNAL_VERSION.length
            + Integer.BYTES
            + PAYLOAD.length
            + payload.length
            + PREVSIG.length
            + previousSignature.length;
    var toVerify = ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
    toVerify.put(EXTERNAL_VERSION);
    toVerify.putInt(version);
    toVerify.put(PAYLOAD);
    toVerify.put(payload);
    toVerify.put(PREVSIG);
    toVerify.put(previousSignature);
    toVerify.flip();
    return toVerify.array();
  }

  public static byte[] generateSealBlockSignaturePayloadV0(SignedBlock block) {
    var keyBytes = block.getKey().toBytes();
    var capacity =
        block.getBlock().length + Integer.BYTES + keyBytes.length + block.getSignature().length;
    var toVerify = ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
    toVerify.put(block.getBlock());
    toVerify.putInt(block.getKey().getAlgorithm().getNumber());
    toVerify.put(keyBytes);
    toVerify.put(block.getSignature());
    toVerify.flip();
    return toVerify.array();
  }
}
