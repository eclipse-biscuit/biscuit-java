package org.biscuitsec.biscuit.crypto;

import org.biscuitsec.biscuit.token.format.ExternalSignature;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;

public final class BlockSignatureBuffer {
    private BlockSignatureBuffer(){}

    public static byte[] getBufferSignature(PublicKey nextPubKey, byte[] data) {
        return getBufferSignature(nextPubKey, data, Optional.empty());
    }

    public static byte[] getBufferSignature(PublicKey nextPubKey, byte[] data, Optional<ExternalSignature> externalSignature) {
        var buffer = ByteBuffer.allocate(4 + data.length + nextPubKey.toBytes().length + externalSignature.map((a) -> a.signature.length).orElse(0)).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(data);
        externalSignature.ifPresent(signature -> buffer.put(signature.signature));
        buffer.putInt(nextPubKey.algorithm.getNumber());
        buffer.put(nextPubKey.toBytes());
        buffer.flip();
        return buffer.array();
    }

    public static byte[] getBufferSealedSignature(PublicKey nextPubKey, byte[] data, byte[] blockSignature) {
        var buffer = ByteBuffer.allocate(4 + data.length + nextPubKey.toBytes().length + blockSignature.length).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(data);
        buffer.putInt(nextPubKey.algorithm.getNumber());
        buffer.put(nextPubKey.toBytes());
        buffer.put(blockSignature);
        buffer.flip();
        return buffer.array();
    }
}
