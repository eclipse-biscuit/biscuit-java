package org.biscuitsec.biscuit.crypto;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.BigIntegers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

final class SECP256R1KeyPair extends KeyPair {

    static final int MINIMUM_SIGNATURE_LENGTH = 68;
    static final int MAXIMUM_SIGNATURE_LENGTH = 72;

    private final BCECPrivateKey privateKey;
    private final BCECPublicKey publicKey;

    private static final String ALGORITHM = "ECDSA";
    private static final String CURVE = "secp256r1";
    private static final ECNamedCurveParameterSpec SECP256R1 = ECNamedCurveTable.getParameterSpec(CURVE);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    SECP256R1KeyPair(byte[] bytes) {
        var privateKeySpec = new ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(bytes), SECP256R1);
        var privateKey = new BCECPrivateKey(ALGORITHM, privateKeySpec, BouncyCastleProvider.CONFIGURATION);

        var publicKeySpec = new ECPublicKeySpec(SECP256R1.getG().multiply(privateKeySpec.getD()), SECP256R1);
        var publicKey = new BCECPublicKey(ALGORITHM, publicKeySpec, BouncyCastleProvider.CONFIGURATION);

        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    SECP256R1KeyPair(SecureRandom rng) {
        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);

        var privateKeySpec = new ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(bytes), SECP256R1);
        var privateKey = new BCECPrivateKey(ALGORITHM, privateKeySpec, BouncyCastleProvider.CONFIGURATION);

        var publicKeySpec = new ECPublicKeySpec(SECP256R1.getG().multiply(privateKeySpec.getD()), SECP256R1);
        var publicKey = new BCECPublicKey(ALGORITHM, publicKeySpec, BouncyCastleProvider.CONFIGURATION);

        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    SECP256R1KeyPair(String hex) {
        this(Utils.hexStringToByteArray(hex));
    }

    public static java.security.PublicKey decode(byte[] data) {
        var params = ECNamedCurveTable.getParameterSpec(CURVE);
        var spec = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
        return new BCECPublicKey(ALGORITHM, spec, BouncyCastleProvider.CONFIGURATION);
    }

    public static Signature getSignature() throws NoSuchAlgorithmException {
        return Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
    }

    @Override
    public byte[] sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sgr = KeyPair.generateSignature(Schema.PublicKey.Algorithm.SECP256R1);
        sgr.initSign(privateKey);
        sgr.update(data);
        return sgr.sign();
    }

    @Override
    public byte[] toBytes() {
        return BigIntegers.asUnsignedByteArray(privateKey.getD());
    }

    @Override
    public String toHex() {
        return Utils.byteArrayToHexString(toBytes());
    }

    @Override
    public PublicKey getPublicKey() {
        return new PublicKey(Schema.PublicKey.Algorithm.SECP256R1, publicKey);
    }

}
