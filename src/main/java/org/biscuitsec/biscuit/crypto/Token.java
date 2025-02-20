package org.biscuitsec.biscuit.crypto;

import org.biscuitsec.biscuit.error.Error;
import io.vavr.control.Either;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

class Token {
    public final ArrayList<byte[]> blocks;
    public final ArrayList<PublicKey> keys;
    public final ArrayList<byte[]> signatures;
    public final KeyPair next;

    public Token(final Signer rootSigner, byte[] message, KeyPair next) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] payload = BlockSignatureBuffer.getBufferSignature(next.public_key(), message);

        byte[] signature = rootSigner.sign(payload);

        this.blocks = new ArrayList<>();
        this.blocks.add(message);
        this.keys = new ArrayList<>();
        this.keys.add(next.public_key());
        this.signatures = new ArrayList<>();
        this.signatures.add(signature);
        this.next = next;
    }

    public Token(final ArrayList<byte[]> blocks, final ArrayList<PublicKey> keys, final ArrayList<byte[]> signatures,
                 final KeyPair next) {
        this.signatures = signatures;
        this.blocks = blocks;
        this.keys = keys;
        this.next = next;
    }

    public Token append(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        byte[] payload = BlockSignatureBuffer.getBufferSignature(keyPair.public_key(), message);
        byte[] signature = this.next.sign(payload);

        Token token = new Token(this.blocks, this.keys, this.signatures, keyPair);
        token.blocks.add(message);
        token.signatures.add(signature);
        token.keys.add(keyPair.public_key());

        return token;
    }

    // FIXME: rust version returns a Result<(), error::Signature>
    public Either<Error, Void> verify(PublicKey root) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey currentKey = root;
        for(int i = 0; i < this.blocks.size(); i++) {
            byte[] block = this.blocks.get(i);
            PublicKey nextKey  = this.keys.get(i);
            byte[] signature = this.signatures.get(i);

            byte[] payload = BlockSignatureBuffer.getBufferSignature(nextKey, block);
            if (KeyPair.verify(currentKey, payload, signature)) {
                currentKey = nextKey;
            } else {
                return Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied"));
            }
        }

        if (this.next.public_key().equals(currentKey)) {
            return Right(null);
        } else {
            return Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied"));
        }
    }
}
