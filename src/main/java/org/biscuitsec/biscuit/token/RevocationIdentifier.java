package org.biscuitsec.biscuit.token;

import org.biscuitsec.biscuit.token.builder.Utils;

import java.util.Base64;

public class RevocationIdentifier {
    private byte[] bytes;

    public RevocationIdentifier(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Creates a RevocationIdentifier from base64 url (RFC4648_URLSAFE)
     * @param b64url serialized revocation identifier
     * @return RevocationIdentifier
     */
    public static RevocationIdentifier fromBase64Url(String b64url) {
        return new RevocationIdentifier(Base64.getDecoder().decode(b64url));
    }

    /**
     * Serializes a revocation identifier as base64 url (RFC4648_URLSAFE)
     * @return String
     */
    public String serializeBase64Url() {
        return Base64.getEncoder().encodeToString(this.bytes);
    }

    public String toHex() {
        return Utils.byteArrayToHexString(this.bytes).toLowerCase();
    }

    public static RevocationIdentifier fromBytes(byte[] bytes) {
        return new RevocationIdentifier(bytes);
    }

    public byte[] getBytes() {
        return this.bytes;
    }
}
