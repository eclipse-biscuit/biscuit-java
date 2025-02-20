package org.biscuitsec.biscuit.crypto;

import biscuit.format.schema.Schema;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;

import static biscuit.format.schema.Schema.PublicKey.Algorithm.*;
import static io.vavr.API.Left;
import static io.vavr.API.Right;

import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @serial exclude
 */
public class SignatureTest {

    @Test
    public void testSerialize() {
        testSerialize(Ed25519, 32);
        testSerialize(SECP256R1, 33); // compressed - 0x02 or 0x03 prefix byte, 32 bytes for X coordinate
    }

    @Test
    public void testThreeMessages() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        testThreeMessages(Ed25519);
        testThreeMessages(SECP256R1);
    }

    @Test
    public void testChangeMessages() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        testChangeMessages(Ed25519);
        testChangeMessages(SECP256R1);
    }

    private static void testSerialize(Schema.PublicKey.Algorithm algorithm, int expectedPublicKeyLength) {
        byte[] seed = {1, 2, 3, 4};
        SecureRandom rng = new SecureRandom(seed);

        KeyPair keypair = KeyPair.generate(algorithm, rng);
        PublicKey pubkey = keypair.getPublicKey();

        byte[] serializedSecretKey = keypair.toBytes();
        byte[] serializedPublicKey = pubkey.toBytes();

        KeyPair deserializedSecretKey = KeyPair.generate(algorithm, serializedSecretKey);
        PublicKey deserializedPublicKey = new PublicKey(algorithm, serializedPublicKey);

        assertEquals(32, serializedSecretKey.length);
        assertEquals(expectedPublicKeyLength, serializedPublicKey.length);

        System.out.println(keypair.toHex());
        System.out.println(deserializedSecretKey.toHex());
        assertArrayEquals(keypair.toBytes(), deserializedSecretKey.toBytes());

        System.out.println(pubkey.toHex());
        System.out.println(deserializedPublicKey.toHex());
        assertEquals(pubkey.toHex(), deserializedPublicKey.toHex());
    }

    private static void testChangeMessages(Schema.PublicKey.Algorithm algorithm) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);

        String message1 = "hello";
        KeyPair root = KeyPair.generate(algorithm, rng);
        KeyPair keypair2 = KeyPair.generate(algorithm, rng);
        Token token1 = new Token(root, message1.getBytes(), keypair2);
        assertEquals(Right(null), token1.verify(new PublicKey(algorithm, root.getPublicKey().key)));

        String message2 = "world";
        KeyPair keypair3 = KeyPair.generate(algorithm, rng);
        Token token2 = token1.append(keypair3, message2.getBytes());
        token2.blocks.set(1, "you".getBytes());
        assertEquals(Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied")),
                token2.verify(new PublicKey(algorithm, root.getPublicKey().key)));

        String message3 = "!!";
        KeyPair keypair4 = KeyPair.generate(algorithm, rng);
        Token token3 = token2.append(keypair4, message3.getBytes());
        assertEquals(Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied")),
                token3.verify(new PublicKey(algorithm, root.getPublicKey().key)));
    }

    private static void testThreeMessages(Schema.PublicKey.Algorithm algorithm) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
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

    @Test
    public void testSerializeBiscuit() throws Error {
        var root = KeyPair.generate(SECP256R1);
        var biscuit = Biscuit.builder(root)
                .addAuthorityFact("user(\"1234\")")
                .addAuthorityCheck("check if operation(\"read\")")
                .build();
        var serialized = biscuit.serialize();
        var unverified = Biscuit.fromBytes(serialized);
        assertDoesNotThrow(() -> unverified.verify(root.getPublicKey()));
    }
}
