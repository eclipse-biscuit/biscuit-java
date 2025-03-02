package org.biscuitsec.biscuit.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;
import org.biscuitsec.biscuit.token.format.ExternalSignature;

public final class BlockSignatureBuffer {
  public static final int HEADER_SIZE = 4;

  private BlockSignatureBuffer() {}

  public static byte[] getBufferSignature(PublicKey nextPubKey, byte[] data) {
    return getBufferSignature(nextPubKey, data, Optional.empty());
  }

  public static byte[] getBufferSignature(
      PublicKey nextPubKey, byte[] data, Optional<ExternalSignature> externalSignature) {
    var buffer =
        ByteBuffer.allocate(
                HEADER_SIZE
                    + data.length
                    + nextPubKey.toBytes().length
                    + externalSignature.map((a) -> a.getSignature().length).orElse(0))
            .order(ByteOrder.LITTLE_ENDIAN);
    buffer.put(data);
    externalSignature.ifPresent(signature -> buffer.put(signature.getSignature()));
    buffer.putInt(nextPubKey.getAlgorithm().getNumber());
    buffer.put(nextPubKey.toBytes());
    buffer.flip();
    return buffer.array();
  }

  public static byte[] getBufferSealedSignature(
      PublicKey nextPubKey, byte[] data, byte[] blockSignature) {
    var buffer =
        ByteBuffer.allocate(
                HEADER_SIZE + data.length + nextPubKey.toBytes().length + blockSignature.length)
            .order(ByteOrder.LITTLE_ENDIAN);
    buffer.put(data);
    buffer.putInt(nextPubKey.getAlgorithm().getNumber());
    buffer.put(nextPubKey.toBytes());
    buffer.put(blockSignature);
    buffer.flip();
    return buffer.array();
  }
}
