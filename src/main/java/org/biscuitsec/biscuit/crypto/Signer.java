package org.biscuitsec.biscuit.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * Interface to enable the cryptographic signature of payload.
 * It can be adapted depending of the needs
 */
public interface Signer {
    /**
     * Sign the payload with the signer key
     *
     * @param payload
     * @return the signature of payload by
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    byte[] sign(byte[] payload) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

    /**
     * Return the public key of the signer and the associated algorithm
     *
     * @return
     */
    PublicKey getPublicKey();
}
