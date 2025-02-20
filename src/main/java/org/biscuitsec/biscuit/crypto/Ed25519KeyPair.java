package org.biscuitsec.biscuit.crypto;

import biscuit.format.schema.Schema;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.biscuitsec.biscuit.token.builder.Utils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

final class Ed25519KeyPair extends KeyPair {

    static final int SIGNATURE_LENGTH = 64;

    private final EdDSAPrivateKey privateKey;
    private final EdDSAPublicKey publicKey;

    private static final EdDSANamedCurveSpec ED_25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

    public Ed25519KeyPair(byte[] bytes) {
        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(bytes, ED_25519);
        EdDSAPrivateKey privKey = new EdDSAPrivateKey(privKeySpec);

        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKey.getA(), ED_25519);
        EdDSAPublicKey pubKey = new EdDSAPublicKey(pubKeySpec);

        this.privateKey = privKey;
        this.publicKey = pubKey;
    }

    public Ed25519KeyPair(SecureRandom rng) {
        byte[] b = new byte[32];
        rng.nextBytes(b);

        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(b, ED_25519);
        EdDSAPrivateKey privKey = new EdDSAPrivateKey(privKeySpec);

        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKey.getA(), ED_25519);
        EdDSAPublicKey pubKey = new EdDSAPublicKey(pubKeySpec);

        this.privateKey = privKey;
        this.publicKey = pubKey;
    }

    public Ed25519KeyPair(String hex) {
        this(Utils.hexStringToByteArray(hex));
    }

    public static java.security.PublicKey decode(byte[] data) {
        return new EdDSAPublicKey(new EdDSAPublicKeySpec(data, ED_25519));
    }

    public static Signature getSignature() throws NoSuchAlgorithmException {
        return new EdDSAEngine(MessageDigest.getInstance(ED_25519.getHashAlgorithm()));
    }

    @Override
    public byte[] sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sgr = KeyPair.generateSignature(Schema.PublicKey.Algorithm.Ed25519);
        sgr.initSign(privateKey);
        sgr.update(data);
        return sgr.sign();
    }

    @Override
    public byte[] toBytes() {
        return privateKey.getSeed();
    }

    @Override
    public String toHex() {
        return Utils.byteArrayToHexString(toBytes());
    }

    @Override
    public PublicKey getPublicKey() {
        return new PublicKey(Schema.PublicKey.Algorithm.Ed25519, this.publicKey);
    }

}
