/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.format;

import biscuit.format.schema.Schema;
import java.util.Set;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Error.FormatError.DeserializationLimitError.Reason;
import org.eclipse.biscuit.token.DeserializationLimit;

/**
 * Checks the settings of a {@link DeserializationLimit} which apply to the token as a whole.
 *
 * <p>These are checked on the protobuf message before any signature is verified. The limits within
 * each block are checked while the block is deserialized, see {@link
 * org.eclipse.biscuit.token.Block#deserialize}.
 */
final class DeserializationLimitChecker {
  private DeserializationLimitChecker() {}

  /** Checks the size of the serialized token, before it is parsed */
  static void checkTokenSize(byte[] slice, DeserializationLimit deserializationLimit)
      throws Error.FormatError {
    require(slice.length <= deserializationLimit.getMaxTokenSize(), Reason.TOKEN_TOO_LARGE);
  }

  /**
   * Checks the number of blocks and whether the token is sealed, before the root key is looked up
   * and before the blocks are examined
   */
  static void checkToken(Schema.Biscuit data, DeserializationLimit deserializationLimit)
      throws Error.FormatError {
    // the authority block counts towards the maximum
    require(data.getBlocksCount() < deserializationLimit.getMaxBlocks(), Reason.TOO_MANY_BLOCKS);
    if (data.getProof().hasFinalSignature()) {
      require(deserializationLimit.getAllowSealedTokens(), Reason.SEALED_TOKENS_NOT_ALLOWED);
    } else if (data.getProof().hasNextSecret()) {
      require(deserializationLimit.getAllowUnsealedTokens(), Reason.UNSEALED_TOKENS_NOT_ALLOWED);
    }
  }

  /**
   * Checks the settings of each signed block: the signing algorithms, the signature version, and
   * whether attenuations may have external signatures
   */
  static void checkSignedBlocks(Schema.Biscuit data, DeserializationLimit deserializationLimit)
      throws Error.FormatError {
    checkSignedBlock(data.getAuthority(), false, deserializationLimit);
    for (Schema.SignedBlock block : data.getBlocksList()) {
      checkSignedBlock(block, true, deserializationLimit);
    }
  }

  private static void checkSignedBlock(
      Schema.SignedBlock block, boolean attenuation, DeserializationLimit deserializationLimit)
      throws Error.FormatError {
    // this is the same condition SerializedBiscuit uses to decide that a block is third party
    boolean external =
        attenuation
            && block.hasExternalSignature()
            && block.getExternalSignature().hasPublicKey()
            && block.getExternalSignature().hasSignature();
    if (attenuation) {
      if (external) {
        require(
            deserializationLimit.getAllowAttenuationsWithExternalSignatures(),
            Reason.ATTENUATIONS_WITH_EXTERNAL_SIGNATURES_NOT_ALLOWED);
      } else {
        require(
            deserializationLimit.getAllowAttenuationsWithoutExternalSignatures(),
            Reason.ATTENUATIONS_WITHOUT_EXTERNAL_SIGNATURES_NOT_ALLOWED);
      }
    }

    Set<Schema.PublicKey.Algorithm> internalAlgorithms =
        deserializationLimit.getAllowedInternalSigningAlgorithms();
    if (internalAlgorithms != null) {
      require(
          internalAlgorithms.contains(block.getNextKey().getAlgorithm()),
          Reason.INTERNAL_SIGNING_ALGORITHM_NOT_ALLOWED);
    }
    // a block without a version uses version 0 signatures
    require(
        block.getVersion() >= deserializationLimit.getMinSignatureVersion(),
        Reason.SIGNATURE_VERSION_TOO_LOW);

    Set<Schema.PublicKey.Algorithm> externalAlgorithms =
        deserializationLimit.getAllowedExternalSigningAlgorithms();
    if (external && externalAlgorithms != null) {
      require(
          externalAlgorithms.contains(block.getExternalSignature().getPublicKey().getAlgorithm()),
          Reason.EXTERNAL_SIGNING_ALGORITHM_NOT_ALLOWED);
    }
  }

  private static void require(boolean condition, Reason reason) throws Error.FormatError {
    if (!condition) {
      throw new Error.FormatError.DeserializationLimitError(reason);
    }
  }
}
