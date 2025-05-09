/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.format;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import io.vavr.control.Option;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.eclipse.biscuit.crypto.BlockSignatureBuffer;
import org.eclipse.biscuit.crypto.KeyDelegate;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.crypto.Signer;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.Block;

/** Intermediate representation of a token before full serialization */
public final class SerializedBiscuit {
  private final SignedBlock authority;
  private final List<SignedBlock> blocks;
  private Proof proof;
  private Option<Integer> rootKeyId;

  public static final int MIN_SCHEMA_VERSION = 3;
  public static final int MAX_SCHEMA_VERSION = 5;

  /**
   * Deserializes a SerializedBiscuit from a byte array
   *
   * @param slice
   * @return
   */
  public static SerializedBiscuit fromBytes(byte[] slice, PublicKey root)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    try {
      Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);

      return fromBytesInner(data, root);
    } catch (InvalidProtocolBufferException e) {
      throw new Error.FormatError.DeserializationError(e.toString());
    }
  }

  /**
   * Deserializes a SerializedBiscuit from a byte array
   *
   * @param slice
   * @return
   */
  public static SerializedBiscuit fromBytes(byte[] slice, KeyDelegate delegate)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    try {
      Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);

      Option<Integer> rootKeyId = Option.none();
      if (data.hasRootKeyId()) {
        rootKeyId = Option.some(data.getRootKeyId());
      }

      Option<PublicKey> root = delegate.getRootKey(rootKeyId);
      if (root.isEmpty()) {
        throw new InvalidKeyException("unknown root key id");
      }

      return fromBytesInner(data, root.get());
    } catch (InvalidProtocolBufferException e) {
      throw new Error.FormatError.DeserializationError(e.toString());
    }
  }

  static SerializedBiscuit fromBytesInner(Schema.Biscuit data, PublicKey root)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    SerializedBiscuit b = SerializedBiscuit.deserialize(data);
    if (data.hasRootKeyId()) {
      b.rootKeyId = Option.some(data.getRootKeyId());
    }

    Either<Error, Void> res = b.verify(root);
    if (res.isLeft()) {
      throw res.getLeft();
    } else {
      return b;
    }
  }

  /**
   * Warning: this deserializes without verifying the signature
   *
   * @param slice
   * @return SerializedBiscuit
   * @throws Error.FormatError.DeserializationError
   */
  public static SerializedBiscuit deserializeUnsafe(byte[] slice)
      throws Error.FormatError.DeserializationError {
    try {
      Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);
      return SerializedBiscuit.deserialize(data);
    } catch (InvalidProtocolBufferException e) {
      throw new Error.FormatError.DeserializationError(e.toString());
    }
  }

  /**
   * Warning: this deserializes without verifying the signature
   *
   * @param data
   * @return SerializedBiscuit
   * @throws Error.FormatError.DeserializationError
   */
  private static SerializedBiscuit deserialize(Schema.Biscuit data)
      throws Error.FormatError.DeserializationError {
    if (data.getAuthority().hasExternalSignature()) {
      throw new Error.FormatError.DeserializationError(
          "the authority block must not contain an external signature");
    }

    SignedBlock authority =
        new SignedBlock(
            data.getAuthority().getBlock().toByteArray(),
            PublicKey.deserialize(data.getAuthority().getNextKey()),
            data.getAuthority().getSignature().toByteArray(),
            Option.none());

    ArrayList<SignedBlock> blocks = new ArrayList<>();
    for (Schema.SignedBlock block : data.getBlocksList()) {
      Option<ExternalSignature> external = Option.none();
      if (block.hasExternalSignature()
          && block.getExternalSignature().hasPublicKey()
          && block.getExternalSignature().hasSignature()) {
        Schema.ExternalSignature ex = block.getExternalSignature();
        external =
            Option.some(
                new ExternalSignature(
                    PublicKey.deserialize(ex.getPublicKey()), ex.getSignature().toByteArray()));
      }
      blocks.add(
          new SignedBlock(
              block.getBlock().toByteArray(),
              PublicKey.deserialize(block.getNextKey()),
              block.getSignature().toByteArray(),
              external));
    }

    // One flags between hasNextSecret() and hasFinalSignature() needs to be set
    if (!data.getProof().hasNextSecret() && !data.getProof().hasFinalSignature()) {
      throw new Error.FormatError.DeserializationError("empty proof");
    }

    // Both flags can’t be set at the same time
    if (data.getProof().hasNextSecret() && data.getProof().hasFinalSignature()) {
      throw new Error.FormatError.DeserializationError("invalid proof");
    }

    final Proof proof;
    if (data.getProof().hasFinalSignature()) {
      proof = new Proof.FinalSignature(data.getProof().getFinalSignature().toByteArray());
    } else {
      final Schema.PublicKey.Algorithm proofAlgorithm =
          blocks.isEmpty()
              ? authority.getKey().getAlgorithm()
              : blocks.get(blocks.size() - 1).getKey().getAlgorithm();
      proof =
          new Proof.NextSecret(
              KeyPair.generate(proofAlgorithm, data.getProof().getNextSecret().toByteArray()));
    }

    Option<Integer> rootKeyId =
        data.hasRootKeyId() ? Option.some(data.getRootKeyId()) : Option.none();

    return new SerializedBiscuit(authority, blocks, proof, rootKeyId);
  }

  /**
   * Serializes a SerializedBiscuit to a byte array
   *
   * @return
   */
  public byte[] serialize() throws Error.FormatError.SerializationError {
    Schema.SignedBlock.Builder authorityBuilder = Schema.SignedBlock.newBuilder();
    SignedBlock authorityBlock = this.authority;
    authorityBuilder.setBlock(ByteString.copyFrom(authorityBlock.getBlock()));
    authorityBuilder.setNextKey(authorityBlock.getKey().serialize());
    authorityBuilder.setSignature(ByteString.copyFrom(authorityBlock.getSignature()));
    Schema.Biscuit.Builder biscuitBuilder = Schema.Biscuit.newBuilder();
    biscuitBuilder.setAuthority(authorityBuilder.build());

    for (SignedBlock b : this.blocks) {
      Schema.SignedBlock.Builder blockBuilder = Schema.SignedBlock.newBuilder();
      blockBuilder.setBlock(ByteString.copyFrom(b.getBlock()));
      blockBuilder.setNextKey(b.getKey().serialize());
      blockBuilder.setSignature(ByteString.copyFrom(b.getSignature()));

      if (b.getExternalSignature().isDefined()) {
        ExternalSignature externalSignature = b.getExternalSignature().get();
        Schema.ExternalSignature.Builder externalSignatureBuilder =
            Schema.ExternalSignature.newBuilder();
        externalSignatureBuilder.setPublicKey(externalSignature.getKey().serialize());
        externalSignatureBuilder.setSignature(
            ByteString.copyFrom(externalSignature.getSignature()));
        blockBuilder.setExternalSignature(externalSignatureBuilder.build());
      }

      biscuitBuilder.addBlocks(blockBuilder.build());
    }

    Schema.Proof.Builder proofBuilder = Schema.Proof.newBuilder();
    if (this.proof.isSealed()) {
      Proof.FinalSignature finalSignature = (Proof.FinalSignature) this.proof;
      proofBuilder.setFinalSignature(ByteString.copyFrom(finalSignature.signature()));
    } else {
      Proof.NextSecret nextSecret = (Proof.NextSecret) this.proof;
      proofBuilder.setNextSecret(ByteString.copyFrom(nextSecret.secretKey().toBytes()));
    }

    biscuitBuilder.setProof(proofBuilder.build());
    if (!this.rootKeyId.isEmpty()) {
      biscuitBuilder.setRootKeyId(this.rootKeyId.get());
    }

    Schema.Biscuit biscuit = biscuitBuilder.build();

    try {
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      biscuit.writeTo(stream);
      return stream.toByteArray();
    } catch (IOException e) {
      throw new Error.FormatError.SerializationError(e.toString());
    }
  }

  public static Either<Error.FormatError, SerializedBiscuit> make(
      final KeyPair root, final Block authority, final KeyPair next) {

    return make(root, Option.none(), authority, next);
  }

  public static Either<Error.FormatError, SerializedBiscuit> make(
      final Signer rootSigner,
      final Option<Integer> rootKeyId,
      final Block authority,
      final KeyPair next) {
    Schema.Block b = authority.serialize();
    try {
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      b.writeTo(stream);
      byte[] block = stream.toByteArray();
      PublicKey nextKey = next.getPublicKey();
      byte[] payload =
          BlockSignatureBuffer.generateBlockSignaturePayloadV0(block, nextKey, Optional.empty());
      byte[] signature = rootSigner.sign(payload);
      SignedBlock signedBlock = new SignedBlock(block, nextKey, signature, Option.none());
      Proof proof = new Proof.NextSecret(next);

      return Right(new SerializedBiscuit(signedBlock, new ArrayList<>(), proof, rootKeyId));
    } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
      return Left(new Error.FormatError.SerializationError(e.toString()));
    }
  }

  public Either<Error.FormatError, SerializedBiscuit> append(
      final KeyPair next, final Block newBlock, Option<ExternalSignature> externalSignature) {
    if (this.proof.isSealed()) {
      return Left(new Error.FormatError.SerializationError("the token is sealed"));
    }

    Schema.Block b = newBlock.serialize();
    try {
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      b.writeTo(stream);

      byte[] block = stream.toByteArray();
      KeyPair secretKey = this.proof.secretKey();
      PublicKey nextKey = next.getPublicKey();

      byte[] payload =
          BlockSignatureBuffer.generateBlockSignaturePayloadV0(
              block, nextKey, externalSignature.toJavaOptional());
      byte[] signature = this.proof.secretKey().sign(payload);

      SignedBlock signedBlock = new SignedBlock(block, nextKey, signature, externalSignature);

      ArrayList<SignedBlock> blocks = new ArrayList<>();
      for (SignedBlock bl : this.blocks) {
        blocks.add(bl);
      }
      blocks.add(signedBlock);

      Proof proof = new Proof.NextSecret(next);

      return Right(new SerializedBiscuit(this.authority, blocks, proof, rootKeyId));
    } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
      return Left(new Error.FormatError.SerializationError(e.toString()));
    }
  }

  public Either<Error, Void> verify(PublicKey root)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    PublicKey currentKey = root;
    Either<Error, PublicKey> res = verifyBlockSignature(this.authority, currentKey);
    if (res.isRight()) {
      currentKey = res.get();
    } else {
      return Left(res.getLeft());
    }

    for (SignedBlock b : this.blocks) {
      res = verifyBlockSignature(b, currentKey);
      if (res.isRight()) {
        currentKey = res.get();
      } else {
        return Left(res.getLeft());
      }
    }

    // System.out.println("signatures verified, checking proof");

    if (!this.proof.isSealed()) {
      // System.out.println("checking secret key");
      // System.out.println("current key: " + currentKey.toHex());
      // System.out.println("key from proof: " + this.proof.secretKey.get().public_key().toHex());
      if (this.proof.secretKey().getPublicKey().equals(currentKey)) {
        // System.out.println("public keys are equal");

        return Right(null);
      } else {
        // System.out.println("public keys are not equal");

        return Left(
            new Error.FormatError.Signature.InvalidSignature(
                "signature error: Verification equation was not satisfied"));
      }
    } else {
      // System.out.println("checking final signature");

      byte[] finalSignature = this.proof.getSignature().get();

      SignedBlock b;
      if (this.blocks.isEmpty()) {
        b = this.authority;
      } else {
        b = this.blocks.get(this.blocks.size() - 1);
      }

      byte[] payload = BlockSignatureBuffer.generateSealBlockSignaturePayloadV0(b);
      if (currentKey.verify(payload, finalSignature)) {
        return Right(null);
      } else {
        return Left(new Error.FormatError.Signature.SealedSignature());
      }
    }
  }

  static Either<Error, PublicKey> verifyBlockSignature(SignedBlock signedBlock, PublicKey publicKey)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

    PublicKey nextKey = signedBlock.getKey();
    byte[] signature = signedBlock.getSignature();

    var signatureLengthError =
        PublicKey.validateSignatureLength(publicKey.getAlgorithm(), signature.length);
    if (signatureLengthError.isPresent()) {
      return Left(signatureLengthError.get());
    }

    ByteBuffer algoBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
    algoBuf.putInt(Integer.valueOf(nextKey.getAlgorithm().getNumber()));
    algoBuf.flip();

    byte[] block = signedBlock.getBlock();
    byte[] payload =
        BlockSignatureBuffer.generateBlockSignaturePayloadV0(
            block, nextKey, signedBlock.getExternalSignature().toJavaOptional());
    if (!publicKey.verify(payload, signature)) {
      return Left(
          new Error.FormatError.Signature.InvalidSignature(
              "signature error: Verification equation was not satisfied"));
    }

    if (signedBlock.getExternalSignature().isDefined()) {
      byte[] externalPayload =
          BlockSignatureBuffer.generateExternalBlockSignaturePayloadV0(block, publicKey);
      ExternalSignature externalSignature = signedBlock.getExternalSignature().get();

      if (!externalSignature.getKey().verify(externalPayload, externalSignature.getSignature())) {
        return Left(
            new Error.FormatError.Signature.InvalidSignature(
                "external signature error: Verification equation was not satisfied"));
      }
    }

    return Right(nextKey);
  }

  public Tuple2<Block, ArrayList<Block>> extractBlocks(SymbolTable symbolTable) throws Error {
    ArrayList<Option<PublicKey>> blockExternalKeys = new ArrayList<>();
    Either<Error.FormatError, Block> authRes =
        Block.fromBytes(this.authority.getBlock(), Option.none());
    if (authRes.isLeft()) {
      throw authRes.getLeft();
    }
    Block authority = authRes.get();
    for (PublicKey pk : authority.getPublicKeys()) {
      symbolTable.insert(pk);
    }
    blockExternalKeys.add(Option.none());

    for (String s : authority.getSymbolTable().symbols()) {
      symbolTable.add(s);
    }

    ArrayList<Block> blocks = new ArrayList<>();
    for (SignedBlock bdata : this.blocks) {
      Option<PublicKey> externalKey = Option.none();
      if (bdata.getExternalSignature().isDefined()) {
        externalKey = Option.some(bdata.getExternalSignature().get().getKey());
      }
      Either<Error.FormatError, Block> blockRes = Block.fromBytes(bdata.getBlock(), externalKey);
      if (blockRes.isLeft()) {
        throw blockRes.getLeft();
      }
      Block block = blockRes.get();

      // blocks with external signatures keep their own symbol table
      if (bdata.getExternalSignature().isDefined()) {
        // symbolTable.insert(bdata.externalSignature.get().key);
        blockExternalKeys.add(Option.some(bdata.getExternalSignature().get().getKey()));
      } else {
        blockExternalKeys.add(Option.none());
        for (String s : block.getSymbolTable().symbols()) {
          symbolTable.add(s);
        }
        for (PublicKey pk : block.getPublicKeys()) {
          symbolTable.insert(pk);
        }
      }

      blocks.add(block);
    }

    return new Tuple2<>(authority, blocks);
  }

  public Either<Error, Void> seal()
      throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    if (this.proof.isSealed()) {
      return Left(new Error.Sealed());
    }

    SignedBlock block;
    if (this.blocks.isEmpty()) {
      block = this.authority;
    } else {
      block = this.blocks.get(this.blocks.size() - 1);
    }

    KeyPair secretKey = this.proof.secretKey();
    byte[] payload = BlockSignatureBuffer.generateSealBlockSignaturePayloadV0(block);
    byte[] signature = secretKey.sign(payload);

    this.proof = new Proof.FinalSignature(signature);

    return Right(null);
  }

  public List<byte[]> revocationIdentifiers() {
    ArrayList<byte[]> l = new ArrayList<>();
    l.add(this.authority.getSignature());

    for (SignedBlock block : this.blocks) {
      l.add(block.getSignature());
    }
    return l;
  }

  SerializedBiscuit(SignedBlock authority, List<SignedBlock> blocks, Proof proof) {
    this.authority = authority;
    this.blocks = blocks;
    this.proof = proof;
    this.rootKeyId = Option.none();
  }

  SerializedBiscuit(
      SignedBlock authority, List<SignedBlock> blocks, Proof proof, Option<Integer> rootKeyId) {
    this.authority = authority;
    this.blocks = blocks;
    this.proof = proof;
    this.rootKeyId = rootKeyId;
  }

  public SignedBlock getAuthority() {
    return authority;
  }

  public List<SignedBlock> getBlocks() {
    return blocks;
  }

  Proof getProof() {
    return proof;
  }

  public Option<Integer> getRootKeyId() {
    return rootKeyId;
  }
}
