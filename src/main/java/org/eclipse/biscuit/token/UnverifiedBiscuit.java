/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import io.vavr.control.Option;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.eclipse.biscuit.crypto.BlockSignatureBuffer;
import org.eclipse.biscuit.crypto.KeyDelegate;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.Check;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.format.ExternalSignature;
import org.eclipse.biscuit.token.format.SerializedBiscuit;

/**
 * UnverifiedBiscuit auth token. UnverifiedBiscuit means it's deserialized without checking
 * signatures.
 */
public class UnverifiedBiscuit {
  protected final Block authority;
  protected final List<Block> blocks;
  protected final SymbolTable symbolTable;
  protected final SerializedBiscuit serializedBiscuit;

  UnverifiedBiscuit(
      Block authority,
      List<Block> blocks,
      SymbolTable symbolTable,
      SerializedBiscuit serializedBiscuit) {
    this.authority = authority;
    this.blocks = blocks;
    this.symbolTable = symbolTable;
    this.serializedBiscuit = serializedBiscuit;
  }

  /**
   * Deserializes a Biscuit token from a base64 url (RFC4648_URLSAFE) string
   *
   * <p>This method uses the default symbol table
   *
   * @param data
   * @return Biscuit
   */
  public static UnverifiedBiscuit fromBase64Url(String data) throws Error {
    return UnverifiedBiscuit.fromBytes(Base64.getUrlDecoder().decode(data));
  }

  /**
   * Deserializes a Biscuit token from a byte array
   *
   * <p>This method uses the default symbol table
   *
   * @param data
   * @return
   */
  public static UnverifiedBiscuit fromBytes(byte[] data) throws Error {
    return UnverifiedBiscuit.fromBytesWithSymbols(data, defaultSymbolTable());
  }

  /**
   * Deserializes a UnverifiedBiscuit from a byte array
   *
   * @param data
   * @return UnverifiedBiscuit
   */
  public static UnverifiedBiscuit fromBytesWithSymbols(byte[] data, SymbolTable symbolTable)
      throws Error {
    SerializedBiscuit ser = SerializedBiscuit.deserializeUnsafe(data);
    return UnverifiedBiscuit.fromSerializedBiscuit(ser, symbolTable);
  }

  /**
   * Fills a UnverifiedBiscuit structure from a deserialized token
   *
   * @return UnverifiedBiscuit
   */
  private static UnverifiedBiscuit fromSerializedBiscuit(
      SerializedBiscuit ser, SymbolTable symbolTable) throws Error {
    Tuple2<Block, ArrayList<Block>> t = ser.extractBlocks(symbolTable);
    Block authority = t._1;
    ArrayList<Block> blocks = t._2;

    return new UnverifiedBiscuit(authority, blocks, symbolTable, ser);
  }

  /**
   * Serializes a token to a byte array
   *
   * @return
   */
  public byte[] serialize() throws Error.FormatError.SerializationError {
    return this.serializedBiscuit.serialize();
  }

  /**
   * Serializes a token to base 64 url String using RFC4648_URLSAFE
   *
   * @return String
   * @throws Error.FormatError.SerializationError
   */
  public String serializeBase64Url() throws Error.FormatError.SerializationError {
    return Base64.getUrlEncoder().encodeToString(serialize());
  }

  /**
   * Creates a Block builder
   *
   * @return
   */
  public org.eclipse.biscuit.token.builder.Block createBlock() {
    return new org.eclipse.biscuit.token.builder.Block();
  }

  /**
   * Generates a new token from an existing one and a new block
   *
   * @param block new block (should be generated from a Block builder)
   * @param algorithm algorithm to use for the ephemeral key pair
   * @return
   */
  public UnverifiedBiscuit attenuate(
      org.eclipse.biscuit.token.builder.Block block, Algorithm algorithm) throws Error {
    SecureRandom rng = new SecureRandom();
    KeyPair keypair = KeyPair.generate(algorithm, rng);
    SymbolTable builderSymbols = new SymbolTable(this.symbolTable);
    return attenuate(rng, keypair, block.build(builderSymbols));
  }

  public UnverifiedBiscuit attenuate(
      final SecureRandom rng, final KeyPair keypair, org.eclipse.biscuit.token.builder.Block block)
      throws Error {
    SymbolTable builderSymbols = new SymbolTable(this.symbolTable);
    return attenuate(rng, keypair, block.build(builderSymbols));
  }

  /**
   * Generates a new token from an existing one and a new block
   *
   * @param rng random number generator
   * @param keypair ephemeral key pair
   * @param block new block (should be generated from a Block builder)
   * @return
   */
  private UnverifiedBiscuit attenuate(final SecureRandom rng, final KeyPair keypair, Block block)
      throws Error {
    UnverifiedBiscuit copiedBiscuit = this.copy();

    if (!copiedBiscuit.symbolTable.disjoint(block.getSymbolTable())) {
      throw new Error.SymbolTableOverlap();
    }

    Either<Error.FormatError, SerializedBiscuit> containerRes =
        copiedBiscuit.serializedBiscuit.append(keypair, block, Option.none());
    if (containerRes.isLeft()) {
      throw containerRes.getLeft();
    }

    SymbolTable symbols = new SymbolTable(copiedBiscuit.symbolTable);
    for (String s : block.getSymbolTable().symbols()) {
      symbols.add(s);
    }

    ArrayList<Block> blocks = new ArrayList<>();
    for (Block b : copiedBiscuit.blocks) {
      blocks.add(b);
    }
    blocks.add(block);
    SerializedBiscuit container = containerRes.get();

    return new UnverifiedBiscuit(copiedBiscuit.authority, blocks, symbols, container);
  }

  // FIXME: attenuate 3rd Party

  public List<RevocationIdentifier> revocationIdentifiers() {
    return this.serializedBiscuit.revocationIdentifiers().stream()
        .map(RevocationIdentifier::fromBytes)
        .collect(Collectors.toList());
  }

  public List<Option<PublicKey>> externalPublicKeys() {
    return Stream.<Option<PublicKey>>concat(
            Stream.of(Option.none()),
            this.serializedBiscuit.getBlocks().stream()
                .map(b -> b.getExternalSignature().map(ExternalSignature::getKey)))
        .collect(Collectors.toList());
  }

  public List<List<Check>> getChecks() {
    ArrayList<List<Check>> l = new ArrayList<>();
    l.add(new ArrayList<>(this.authority.getChecks()));

    for (Block b : this.blocks) {
      l.add(new ArrayList<>(b.getChecks()));
    }

    return l;
  }

  public List<Option<String>> getContext() {
    ArrayList<Option<String>> res = new ArrayList<>();
    if (this.authority.getContext().isEmpty()) {
      res.add(Option.none());
    } else {
      res.add(Option.some(this.authority.getContext()));
    }

    for (Block b : this.blocks) {
      if (b.getContext().isEmpty()) {
        res.add(Option.none());
      } else {
        res.add(Option.some(b.getContext()));
      }
    }

    return res;
  }

  public Option<Integer> getRootKeyId() {
    return this.serializedBiscuit.getRootKeyId();
  }

  public SerializedBiscuit getContainer() {
    return this.serializedBiscuit;
  }

  public int blockCount() {
    return 1 + blocks.size();
  }

  public Option<PublicKey> blockExternalKey(int index) {
    if (index == 0) {
      return authority.getExternalKey();
    } else {
      return blocks.get(index - 1).getExternalKey();
    }
  }

  public List<PublicKey> blockPublicKeys(int index) {
    if (index == 0) {
      return authority.getPublicKeys();
    } else {
      return blocks.get(index - 1).getPublicKeys();
    }
  }

  /** Generates a third party block request from a token */
  public ThirdPartyBlockRequest thirdPartyRequest() {
    PublicKey previousKey;
    if (this.serializedBiscuit.getBlocks().isEmpty()) {
      previousKey = this.serializedBiscuit.getAuthority().getKey();
    } else {
      previousKey =
          this.serializedBiscuit
              .getBlocks()
              .get(this.serializedBiscuit.getBlocks().size() - 1)
              .getKey();
    }

    return new ThirdPartyBlockRequest(previousKey);
  }

  /** Generates a third party block request from a token */
  public UnverifiedBiscuit appendThirdPartyBlock(
      PublicKey externalKey, ThirdPartyBlockContents blockResponse)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    PublicKey previousKey;
    if (this.serializedBiscuit.getBlocks().isEmpty()) {
      previousKey = this.serializedBiscuit.getAuthority().getKey();
    } else {
      previousKey =
          this.serializedBiscuit
              .getBlocks()
              .get(this.serializedBiscuit.getBlocks().size() - 1)
              .getKey();
    }
    KeyPair nextKeyPair = KeyPair.generate(previousKey.getAlgorithm());
    byte[] payload =
        BlockSignatureBuffer.generateExternalBlockSignaturePayloadV0(
            blockResponse.getPayload(), previousKey);
    if (!externalKey.verify(payload, blockResponse.getSignature())) {
      throw new Error.FormatError.Signature.InvalidSignature(
          "signature error: Verification equation was not satisfied");
    }

    Either<Error.FormatError, Block> res =
        Block.fromBytes(blockResponse.getPayload(), Option.some(externalKey));
    if (res.isLeft()) {
      throw res.getLeft();
    }

    Block block = res.get();

    ExternalSignature externalSignature =
        new ExternalSignature(externalKey, blockResponse.getSignature());

    UnverifiedBiscuit copiedBiscuit = this.copy();

    Either<Error.FormatError, SerializedBiscuit> containerRes =
        copiedBiscuit.serializedBiscuit.append(nextKeyPair, block, Option.some(externalSignature));
    if (containerRes.isLeft()) {
      throw containerRes.getLeft();
    }

    SerializedBiscuit container = containerRes.get();

    SymbolTable symbols = new SymbolTable(copiedBiscuit.symbolTable);

    ArrayList<Block> blocks = new ArrayList<>();
    for (Block b : copiedBiscuit.blocks) {
      blocks.add(b);
    }
    blocks.add(block);

    return new UnverifiedBiscuit(copiedBiscuit.authority, blocks, symbols, container);
  }

  /** Prints a token's content */
  public String print() {
    StringBuilder s = new StringBuilder();
    s.append("UnverifiedBiscuit {\n\tsymbols: ");
    s.append(this.symbolTable.getAllSymbols());
    s.append("\n\tauthority: ");
    s.append(this.authority.print(this.symbolTable));
    s.append("\n\tblocks: [\n");
    for (Block b : this.blocks) {
      s.append("\t\t");
      s.append(b.print(this.symbolTable));
      s.append("\n");
    }
    s.append("\t]\n}");

    return s.toString();
  }

  /** Default symbols list */
  public static SymbolTable defaultSymbolTable() {
    return new SymbolTable();
  }

  @Override
  protected Object clone() throws CloneNotSupportedException {
    return super.clone();
  }

  public UnverifiedBiscuit copy() throws Error {
    return UnverifiedBiscuit.fromBytes(this.serialize());
  }

  public Biscuit verify(PublicKey publicKey)
      throws Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    SerializedBiscuit serializedBiscuit = this.serializedBiscuit;
    var result = serializedBiscuit.verify(publicKey);
    if (result.isLeft()) {
      throw result.getLeft();
    }
    return Biscuit.fromSerializedBiscuit(serializedBiscuit, this.symbolTable);
  }

  public Biscuit verify(KeyDelegate delegate)
      throws Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    SerializedBiscuit serializedBiscuit = this.serializedBiscuit;

    Option<PublicKey> root = delegate.getRootKey(serializedBiscuit.getRootKeyId());
    if (root.isEmpty()) {
      throw new InvalidKeyException("unknown root key id");
    }

    var result = serializedBiscuit.verify(root.get());
    if (result.isLeft()) {
      throw result.getLeft();
    }
    return Biscuit.fromSerializedBiscuit(serializedBiscuit, this.symbolTable);
  }
}
