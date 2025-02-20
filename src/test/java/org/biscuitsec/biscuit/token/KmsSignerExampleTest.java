package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.crypto.Signer;
import org.biscuitsec.biscuit.error.Error;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Testcontainers
public class KmsSignerExampleTest {

    private static final DockerImageName LOCALSTACK_IMAGE = DockerImageName.parse("localstack/localstack:4.0.3");

    @Container
    public static LocalStackContainer LOCALSTACK = new LocalStackContainer(LOCALSTACK_IMAGE)
            .withServices(LocalStackContainer.Service.KMS);

    private KmsClient kmsClient;
    private String kmsKeyId;

    @BeforeEach
    public void setup() {
        var credentials = AwsBasicCredentials.create(LOCALSTACK.getAccessKey(), LOCALSTACK.getSecretKey());
        kmsClient = KmsClient.builder()
                .endpointOverride(LOCALSTACK.getEndpointOverride(LocalStackContainer.Service.KMS))
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .region(Region.of(LOCALSTACK.getRegion()))
                .build();

        // ECC_NIST_P256 == SECP256R1
        kmsKeyId = kmsClient.createKey(b -> b
                .keySpec(KeySpec.ECC_NIST_P256)
                .keyUsage(KeyUsageType.SIGN_VERIFY)
                .build()
        ).keyMetadata().keyId();
    }

    @Test
    public void testCreateBiscuitWithRemoteSigner() throws Error {
        var getPublicKeyResponse = kmsClient.getPublicKey(b -> b.keyId(kmsKeyId).build());
        var x509EncodedPublicKey = getPublicKeyResponse.publicKey().asByteArray();
        var sec1CompressedEncodedPublicKey = convertDEREncodedX509PublicKeyToSEC1CompressedEncodedPublicKey(x509EncodedPublicKey);
        var publicKey = new PublicKey(Algorithm.SECP256R1, sec1CompressedEncodedPublicKey);
        var signer = new Signer() {
            @Override
            public byte[] sign(byte[] bytes) {
                var signResponse = kmsClient.sign(b -> b
                        .keyId(kmsKeyId)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .message(SdkBytes.fromByteArray(bytes))
                );
                return signResponse.signature().asByteArray();
            }

            @Override
            public PublicKey getPublicKey() {
                return publicKey;
            }
        };
        var biscuit = Biscuit.builder(signer)
                .addAuthorityFact("user(\"1234\")")
                .addAuthorityCheck("check if operation(\"read\")")
                .build();
        var serializedBiscuit = biscuit.serialize();
        var deserializedUnverifiedBiscuit = Biscuit.fromBytes(serializedBiscuit);
        var verifiedBiscuit = assertDoesNotThrow(() -> deserializedUnverifiedBiscuit.verify(publicKey));

        System.out.println(verifiedBiscuit.print());
    }

    private static byte[] convertDEREncodedX509PublicKeyToSEC1CompressedEncodedPublicKey(byte[] publicKeyBytes) {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(publicKeyBytes))) {

            // Parse the ASN.1 encoded public key bytes
            var asn1Primitive = asn1InputStream.readObject();
            var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1Primitive);

            // Extract the public key data
            var publicKeyDataBitString = subjectPublicKeyInfo.getPublicKeyData();
            byte[] publicKeyData = publicKeyDataBitString.getBytes();

            // Parse the public key data to get the elliptic curve point
            var ecParameters = ECNamedCurveTable.getByName("secp256r1");
            var ecPoint = ecParameters.getCurve().decodePoint(publicKeyData);
            return ecPoint.getEncoded(true);
        } catch (IOException e) {
            throw new RuntimeException("Error converting DER-encoded X.509 to SEC1 compressed format", e);
        }
    }
}
