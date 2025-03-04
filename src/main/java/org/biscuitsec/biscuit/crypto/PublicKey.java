package org.biscuitsec.biscuit.crypto;

import biscuit.format.schema.Schema;
import biscuit.format.schema.Schema.PublicKey.Algorithm;
import com.google.protobuf.ByteString;
import java.util.Optional;
import java.util.Set;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

public final class PublicKey {

  private final java.security.PublicKey key;
  private final Algorithm algorithm;

  private static final Set<Algorithm> SUPPORTED_ALGORITHMS =
      Set.of(Algorithm.Ed25519, Algorithm.SECP256R1);

  public PublicKey(Algorithm algorithm, java.security.PublicKey publicKey) {
    this.key = publicKey;
    this.algorithm = algorithm;
  }

  public PublicKey(Algorithm algorithm, byte[] data) {
    if (algorithm == Algorithm.Ed25519) {
      this.key = Ed25519KeyPair.decode(data);
    } else if (algorithm == Algorithm.SECP256R1) {
      this.key = SECP256R1KeyPair.decode(data);
    } else {
      throw new IllegalArgumentException("Invalid algorithm");
    }
    this.algorithm = algorithm;
  }

  public PublicKey(Algorithm algorithm, String hex) {
    byte[] data = Utils.hexStringToByteArray(hex);
    if (algorithm == Algorithm.Ed25519) {
      this.key = Ed25519KeyPair.decode(data);
    } else if (algorithm == Algorithm.SECP256R1) {
      this.key = SECP256R1KeyPair.decode(data);
    } else {
      throw new IllegalArgumentException("Invalid algorithm");
    }
    this.algorithm = algorithm;
  }

  public byte[] toBytes() {
    if (getAlgorithm() == Algorithm.Ed25519) {
      return ((EdDSAPublicKey) getKey()).getAbyte();
    } else if (getAlgorithm() == Algorithm.SECP256R1) {
      return ((BCECPublicKey) getKey()).getQ().getEncoded(true); // true = compressed
    } else {
      throw new IllegalArgumentException("Invalid algorithm");
    }
  }

  public String toHex() {
    return Utils.byteArrayToHexString(this.toBytes());
  }


  public Schema.PublicKey serialize() {
    Schema.PublicKey.Builder publicKey = Schema.PublicKey.newBuilder();
    publicKey.setKey(ByteString.copyFrom(this.toBytes()));
    publicKey.setAlgorithm(this.getAlgorithm());
    return publicKey.build();
  }

  public static PublicKey deserialize(Schema.PublicKey pk)
      throws Error.FormatError.DeserializationError {
    if (!pk.hasAlgorithm() || !pk.hasKey() || !SUPPORTED_ALGORITHMS.contains(pk.getAlgorithm())) {
      throw new Error.FormatError.DeserializationError("Invalid public key");
    }
    return new PublicKey(pk.getAlgorithm(), pk.getKey().toByteArray());
  }

  public static Optional<Error> validateSignatureLength(Algorithm algorithm, int length) {
    Optional<Error> error = Optional.empty();
    if (algorithm == Algorithm.Ed25519) {
      if (length != Ed25519KeyPair.SIGNATURE_LENGTH) {
        error = Optional.of(new Error.FormatError.Signature.InvalidSignatureSize(length));
      }
    } else if (algorithm == Algorithm.SECP256R1) {
      if (length < SECP256R1KeyPair.MINIMUM_SIGNATURE_LENGTH
          || length > SECP256R1KeyPair.MAXIMUM_SIGNATURE_LENGTH) {
        error = Optional.of(new Error.FormatError.Signature.InvalidSignatureSize(length));
      }
    } else {
      error =
          Optional.of(new Error.FormatError.Signature.InvalidSignature("unsupported algorithm"));
    }
    return error;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    PublicKey publicKey = (PublicKey) o;

    return getKey().equals(publicKey.getKey());
  }

  @Override
  public int hashCode() {
    return getKey().hashCode();
  }

  @Override
  public String toString() {
    if (getAlgorithm() == Algorithm.Ed25519) {
      return "ed25519/" + toHex().toLowerCase();
    } else if (getAlgorithm() == Algorithm.SECP256R1) {
      return "secp256r1/" + toHex().toLowerCase();
    } else {
      return null;
    }
  }

  public java.security.PublicKey getKey() {
    return key;
  }

  public Algorithm getAlgorithm() {
    return algorithm;
  }
}
