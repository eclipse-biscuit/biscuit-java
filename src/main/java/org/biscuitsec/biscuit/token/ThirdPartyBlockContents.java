package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.error.Error;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

public class ThirdPartyBlockContents {
    byte[] payload;
    byte[] signature;
    PublicKey publicKey;

    ThirdPartyBlockContents(byte[] payload, byte[] signature, PublicKey publicKey) {
        this.payload = payload;
        this.signature = signature;
        this.publicKey = publicKey;
    }

    public Schema.ThirdPartyBlockContents serialize() throws Error.FormatError.SerializationError {
        Schema.ThirdPartyBlockContents.Builder b = Schema.ThirdPartyBlockContents.newBuilder();
        b.setPayload(ByteString.copyFrom(this.payload));
        b.setExternalSignature(b.getExternalSignatureBuilder()
                .setSignature(ByteString.copyFrom(this.signature))
                .setPublicKey(this.publicKey.serialize())
                .build());

        return b.build();
    }

    static public ThirdPartyBlockContents deserialize(Schema.ThirdPartyBlockContents b) throws Error.FormatError.DeserializationError {
        byte[] payload = b.getPayload().toByteArray();
        byte[] signature = b.getExternalSignature().getSignature().toByteArray();
        PublicKey publicKey = PublicKey.deserialize(b.getExternalSignature().getPublicKey());

        return new ThirdPartyBlockContents(payload, signature, publicKey);
    }

    static public ThirdPartyBlockContents fromBytes(byte[] slice) throws InvalidProtocolBufferException, Error.FormatError.DeserializationError {
        return ThirdPartyBlockContents.deserialize(Schema.ThirdPartyBlockContents.parseFrom(slice));
    }

    public byte[] toBytes() throws IOException, Error.FormatError.SerializationError {
        Schema.ThirdPartyBlockContents b = this.serialize();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        b.writeTo(stream);
        return stream.toByteArray();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ThirdPartyBlockContents that = (ThirdPartyBlockContents) o;

        if (!Arrays.equals(payload, that.payload)) return false;
        if (!Arrays.equals(signature, that.signature)) return false;
        return Objects.equals(publicKey, that.publicKey);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(payload);
        result = 31 * result + Arrays.hashCode(signature);
        result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "ThirdPartyBlockContents{" +
                "payload=" + Arrays.toString(payload) +
                ", signature=" + Arrays.toString(signature) +
                ", publicKey=" + publicKey +
                '}';
    }
}
