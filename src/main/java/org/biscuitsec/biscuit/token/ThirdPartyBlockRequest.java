package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema;
import com.google.protobuf.InvalidProtocolBufferException;
import io.vavr.control.Either;
import io.vavr.control.Option;
import org.biscuitsec.biscuit.crypto.BlockSignatureBuffer;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.crypto.Signer;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.builder.Block;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Objects;

public class ThirdPartyBlockRequest {
    PublicKey previousKey;

    ThirdPartyBlockRequest(PublicKey previousKey) {
        this.previousKey = previousKey;
    }

    public Either<Error.FormatError, ThirdPartyBlockContents> createBlock(final Signer externalSigner, Block blockBuilder) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        SymbolTable symbols = new SymbolTable();
        org.biscuitsec.biscuit.token.Block block = blockBuilder.build(symbols, Option.some(externalSigner.getPublicKey()));

        Either<Error.FormatError, byte[]> res = block.toBytes();
        if (res.isLeft()) {
            return Either.left(res.getLeft());
        }

        byte[] serializedBlock = res.get();
        byte[] payload = BlockSignatureBuffer.getBufferSignature(this.previousKey, serializedBlock);
        byte[] signature = externalSigner.sign(payload);

        PublicKey publicKey = externalSigner.getPublicKey();

        return Either.right(new ThirdPartyBlockContents(serializedBlock, signature, publicKey));
    }

    public Schema.ThirdPartyBlockRequest serialize() throws Error.FormatError.SerializationError {
        Schema.ThirdPartyBlockRequest.Builder b = Schema.ThirdPartyBlockRequest.newBuilder();
        b.setPreviousKey(this.previousKey.serialize());

        return b.build();
    }

    static public ThirdPartyBlockRequest deserialize(Schema.ThirdPartyBlockRequest b) throws Error.FormatError.DeserializationError {
        PublicKey previousKey = PublicKey.deserialize(b.getPreviousKey());
        return new ThirdPartyBlockRequest(previousKey);
    }

    static public ThirdPartyBlockRequest fromBytes(byte[] slice) throws InvalidProtocolBufferException, Error.FormatError.DeserializationError {
        return ThirdPartyBlockRequest.deserialize(Schema.ThirdPartyBlockRequest.parseFrom(slice));
    }

    public byte[] toBytes() throws IOException, Error.FormatError.SerializationError {
        Schema.ThirdPartyBlockRequest b = this.serialize();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        b.writeTo(stream);
        return stream.toByteArray();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ThirdPartyBlockRequest that = (ThirdPartyBlockRequest) o;

        return Objects.equals(previousKey, that.previousKey);
    }

    @Override
    public int hashCode() {
        return previousKey != null ? previousKey.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "ThirdPartyBlockRequest{" +
                "previousKey=" + previousKey +
                '}';
    }
}

