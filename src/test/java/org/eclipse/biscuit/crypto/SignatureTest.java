/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import static io.vavr.API.Right;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import biscuit.format.schema.Schema;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.Biscuit;
import org.junit.jupiter.api.Test;

/**
 * @serial exclude
 */
public class SignatureTest {
  @Test
  public void testSerialize() throws Error.FormatError {
    prTestSerialize(Schema.PublicKey.Algorithm.Ed25519, 32);
    prTestSerialize(
        // compressed - 0x02 or 0x03 prefix byte, 32 bytes for X coordinate
        Schema.PublicKey.Algorithm.SECP256R1, 33);
  }

  @Test
  public void testHex() throws Error.FormatError {
    prGenSigKeys(Schema.PublicKey.Algorithm.SECP256R1);
    prGenSigKeys(Schema.PublicKey.Algorithm.Ed25519);
  }

  @Test
  public void testThreeMessages()
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    prTestThreeMessages(Schema.PublicKey.Algorithm.Ed25519);
    prTestThreeMessages(Schema.PublicKey.Algorithm.SECP256R1);
  }

  @Test
  public void testSerializeBiscuit() throws Error {
    var root = KeyPair.generate(Schema.PublicKey.Algorithm.SECP256R1);
    var biscuit =
        Biscuit.builder(root)
            .addAuthorityFact("user(\"1234\")")
            .addAuthorityCheck("check if operation(\"read\")")
            .build();
    var serialized = biscuit.serialize();
    var unverified = Biscuit.fromBytes(serialized);
    assertDoesNotThrow(() -> unverified.verify(root.getPublicKey()));
  }

  @Test
  void testInvalidSepc256r1Key() {
    assertThrows(
        Error.FormatError.InvalidKeySize.class,
        () -> KeyPair.generate(Schema.PublicKey.Algorithm.SECP256R1, "badkey".getBytes()));
  }

  @Test
  void testInvalidEd25519Key() {
    assertThrows(
        Error.FormatError.InvalidKeySize.class,
        () -> KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, "badkey".getBytes()));
  }

  @Test
  void testInvalidSepc256r1PublicKey() {
    assertThrows(
        Error.FormatError.InvalidKey.class,
        () -> PublicKey.load(Schema.PublicKey.Algorithm.SECP256R1, "badkey".getBytes()));
  }

  @Test
  void testInvalidEd25519PublicKey() {
    assertThrows(
        Error.FormatError.InvalidKey.class,
        () -> PublicKey.load(Schema.PublicKey.Algorithm.Ed25519, "badkey".getBytes()));
  }

  private static void prTestSerialize(
      Schema.PublicKey.Algorithm algorithm, int expectedPublicKeyLength) throws Error.FormatError {
    byte[] seed = {1, 2, 3, 4};
    SecureRandom rng = new SecureRandom(seed);

    KeyPair keypair = KeyPair.generate(algorithm, rng);
    PublicKey pubkey = keypair.getPublicKey();

    byte[] serializedSecretKey = keypair.toBytes();
    byte[] serializedPublicKey = pubkey.toBytes();

    final KeyPair deserializedSecretKey = KeyPair.generate(algorithm, serializedSecretKey);
    final PublicKey deserializedPublicKey = PublicKey.load(algorithm, serializedPublicKey);

    assertEquals(32, serializedSecretKey.length);
    assertEquals(expectedPublicKeyLength, serializedPublicKey.length);

    System.out.println(keypair.toHex());
    System.out.println(deserializedSecretKey.toHex());
    assertArrayEquals(keypair.toBytes(), deserializedSecretKey.toBytes());

    System.out.println(pubkey.toHex());
    System.out.println(deserializedPublicKey.toHex());
    assertEquals(pubkey.toHex(), deserializedPublicKey.toHex());
  }

  private static void prTestThreeMessages(Schema.PublicKey.Algorithm algorithm)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    byte[] seed = {0, 0, 0, 0};
    SecureRandom rng = new SecureRandom(seed);

    String message1 = "hello";
    KeyPair root = KeyPair.generate(algorithm, rng);
    KeyPair keypair2 = KeyPair.generate(algorithm, rng);
    System.out.println("root key: " + root.toHex());
    System.out.println("keypair2: " + keypair2.toHex());
    System.out.println("root key public: " + root.getPublicKey().toHex());
    System.out.println("keypair2 public: " + keypair2.getPublicKey().toHex());

    Token token1 = new Token(root, message1.getBytes(), keypair2);
    assertEquals(Right(null), token1.verify(root.getPublicKey()));

    String message2 = "world";
    KeyPair keypair3 = KeyPair.generate(algorithm, rng);
    Token token2 = token1.append(keypair3, message2.getBytes());
    assertEquals(Right(null), token2.verify(root.getPublicKey()));

    String message3 = "!!";
    KeyPair keypair4 = KeyPair.generate(algorithm, rng);
    Token token3 = token2.append(keypair4, message3.getBytes());
    assertEquals(Right(null), token3.verify(root.getPublicKey()));
  }

  private static void prGenSigKeys(Schema.PublicKey.Algorithm algorithm) throws Error.FormatError {
    var keypair = KeyPair.generate(algorithm);
    var pubKey = keypair.getPublicKey();
    var privHexString = keypair.toHex();
    var pubKeyString = pubKey.toHex();
    System.out.println(algorithm + " Keypair hex " + privHexString);
    System.out.println(algorithm + " pubKey hex " + pubKeyString);
    var pubKey2 = PublicKey.load(algorithm, pubKeyString);
    var keyPair2 = KeyPair.generate(algorithm, privHexString);
    System.out.println(algorithm + " Keypair2 hex " + keyPair2.toHex());
    System.out.println(algorithm + " pubKey hex " + pubKey2.toHex());
    assertEquals(keypair.toHex(), keyPair2.toHex(), "keypair hex");
    assertEquals(pubKey.toHex(), pubKey2.toHex(), "public keys hex equals");
    assertEquals(pubKey, pubKey2, "public keys equals");
  }
}
