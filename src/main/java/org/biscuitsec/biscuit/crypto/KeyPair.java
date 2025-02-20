package org.biscuitsec.biscuit.crypto;


import biscuit.format.schema.Schema.PublicKey.Algorithm;
import net.i2p.crypto.eddsa.Utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Private and public key.
 */
public abstract class KeyPair implements Signer {

    public static KeyPair generate(Algorithm algorithm) {
        return generate(algorithm, new SecureRandom());
    }

    public static KeyPair generate(Algorithm algorithm, String hex) {
        return generate(algorithm, Utils.hexToBytes(hex));
    }

    public static KeyPair generate(Algorithm algorithm, byte[] bytes) {
        if (algorithm == Algorithm.Ed25519) {
            return new Ed25519KeyPair(bytes);
        } else if (algorithm == Algorithm.SECP256R1) {
            return new SECP256R1KeyPair(bytes);
        } else {
            throw new IllegalArgumentException("Unsupported algorithm");
        }
    }

    public static KeyPair generate(Algorithm algorithm, SecureRandom rng) {
        if (algorithm == Algorithm.Ed25519) {
            return new Ed25519KeyPair(rng);
        } else if (algorithm == Algorithm.SECP256R1) {
            return new SECP256R1KeyPair(rng);
        } else {
            throw new IllegalArgumentException("Unsupported algorithm");
        }
    }

    public static Signature generateSignature(Algorithm algorithm) throws NoSuchAlgorithmException {
        if (algorithm == Algorithm.Ed25519) {
            return Ed25519KeyPair.getSignature();
        } else if (algorithm == Algorithm.SECP256R1) {
            return SECP256R1KeyPair.getSignature();
        } else {
            throw new NoSuchAlgorithmException("Unsupported algorithm");
        }
    }

    public static boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sgr = KeyPair.generateSignature(publicKey.algorithm);
        sgr.initVerify(publicKey.key);
        sgr.update(data);
        return sgr.verify(signature);
    }

    public abstract byte[] toBytes();

    public abstract String toHex();

    @Override
    public abstract PublicKey getPublicKey();
}
