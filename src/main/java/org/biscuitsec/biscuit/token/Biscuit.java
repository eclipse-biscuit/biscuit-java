package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import org.biscuitsec.biscuit.crypto.KeyDelegate;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.format.SerializedBiscuit;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import io.vavr.control.Option;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Biscuit auth token
 */
public class Biscuit extends UnverifiedBiscuit {
    /**
     * Creates a token builder
     * <p>
     * this function uses the default symbol table
     *
     * @param root root private key
     * @return
     */
    public static org.biscuitsec.biscuit.token.builder.Biscuit builder(final org.biscuitsec.biscuit.crypto.Signer root) {
        return new org.biscuitsec.biscuit.token.builder.Biscuit(new SecureRandom(), root);
    }

    /**
     * Creates a token builder
     * <p>
     * this function uses the default symbol table
     *
     * @param rng  random number generator
     * @param root root private key
     * @return
     */
    public static org.biscuitsec.biscuit.token.builder.Biscuit builder(final SecureRandom rng, final KeyPair root) {
        return new org.biscuitsec.biscuit.token.builder.Biscuit(rng, root);
    }

    /**
     * Creates a token builder
     *
     * @param rng  random number generator
     * @param root root private key
     * @return
     */
    public static org.biscuitsec.biscuit.token.builder.Biscuit builder(final SecureRandom rng, final org.biscuitsec.biscuit.crypto.Signer root, final Option<Integer> rootKeyId) {
        return new org.biscuitsec.biscuit.token.builder.Biscuit(rng, root, rootKeyId);
    }

    /**
     * Creates a token
     *
     * @param rng       random number generator
     * @param root      root private key
     * @param authority authority block
     * @return Biscuit
     */
    public static Biscuit make(final SecureRandom rng, final org.biscuitsec.biscuit.crypto.Signer root, final Block authority) throws Error.FormatError {
        return Biscuit.make(rng, root, Option.none(), authority);
    }

    /**
     * Creates a token
     *
     * @param rng       random number generator
     * @param root      root private key
     * @param authority authority block
     * @return Biscuit
     */
    public static Biscuit make(final SecureRandom rng, final org.biscuitsec.biscuit.crypto.Signer root, final Integer rootKeyId, final Block authority) throws Error.FormatError {
        return Biscuit.make(rng, root, Option.of(rootKeyId), authority);
    }

    /**
     * Creates a token
     *
     * @param rng       random number generator
     * @param root      root private key
     * @param authority authority block
     * @return Biscuit
     */
    static private Biscuit make(final SecureRandom rng, final org.biscuitsec.biscuit.crypto.Signer root, final Option<Integer> rootKeyId, final Block authority) throws Error.FormatError {
        ArrayList<Block> blocks = new ArrayList<>();

        KeyPair next = KeyPair.generate(root.getPublicKey().algorithm, rng);

        for(PublicKey pk:  authority.publicKeys) {
            authority.symbols.insert(pk);
        }

        Either<Error.FormatError, SerializedBiscuit> container = SerializedBiscuit.make(root, rootKeyId, authority, next);
        if (container.isLeft()) {
            throw container.getLeft();
        } else {
            SerializedBiscuit s = container.get();
            List<byte[]> revocationIds = s.revocationIdentifiers();

            Option<SerializedBiscuit> c = Option.some(s);
            return new Biscuit(authority, blocks, authority.symbols, s, revocationIds);
        }
    }

    Biscuit(Block authority, List<Block> blocks, SymbolTable symbols, SerializedBiscuit serializedBiscuit,
            List<byte[]> revocationIds) {
        super(authority, blocks, symbols, serializedBiscuit,  revocationIds);
    }

    /**
     * Deserializes a Biscuit token from a base64 url (RFC4648_URLSAFE) string
     * <p>
     * This checks the signature, but does not verify that the first key is the root key,
     * to allow appending blocks without knowing about the root key.
     * <p>
     * The root key check is performed in the verify method
     * <p>
     * This method uses the default symbol table
     *
     * @param data
     * @return Biscuit
     */
    static public Biscuit fromBase64Url(String data, PublicKey root) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        return Biscuit.fromBytes(Base64.getUrlDecoder().decode(data), root);
    }

    /**
     * Deserializes a Biscuit token from a base64 url (RFC4648_URLSAFE) string
     * <p>
     * This checks the signature, but does not verify that the first key is the root key,
     * to allow appending blocks without knowing about the root key.
     * <p>
     * The root key check is performed in the verify method
     * <p>
     * This method uses the default symbol table
     *
     * @param data
     * @return Biscuit
     */
    static public Biscuit fromBase64Url(String data, KeyDelegate delegate) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        return Biscuit.fromBytes(Base64.getUrlDecoder().decode(data), delegate);
    }

    /**
     * Deserializes a Biscuit token from a byte array
     * <p>
     * This checks the signature, but does not verify that the first key is the root key,
     * to allow appending blocks without knowing about the root key.
     * <p>
     * The root key check is performed in the verify method
     * <p>
     * This method uses the default symbol table
     *
     * @param data
     * @return
     */
    static public Biscuit fromBytes(byte[] data, PublicKey root) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        return fromBytesWithSymbols(data, root, defaultSymbolTable());
    }

    /**
     * Deserializes a Biscuit token from a byte array
     * <p>
     * This checks the signature, but does not verify that the first key is the root key,
     * to allow appending blocks without knowing about the root key.
     * <p>
     * The root key check is performed in the verify method
     * <p>
     * This method uses the default symbol table
     *
     * @param data
     * @return
     */
    static public Biscuit fromBytes(byte[] data, KeyDelegate delegate) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        return fromBytesWithSymbols(data, delegate, defaultSymbolTable());
    }

    /**
     * Deserializes a Biscuit token from a byte array
     * <p>
     * This checks the signature, but does not verify that the first key is the root key,
     * to allow appending blocks without knowing about the root key.
     * <p>
     * The root key check is performed in the verify method
     *
     * @param data
     * @return
     */
    static public Biscuit fromBytesWithSymbols(byte[] data, PublicKey root, SymbolTable symbols) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        //System.out.println("will deserialize and verify token");
        SerializedBiscuit ser = SerializedBiscuit.fromBytes(data, root);
        //System.out.println("deserialized token, will populate Biscuit structure");

        return Biscuit.fromSerializedBiscuit(ser, symbols);
    }

    /**
     * Deserializes a Biscuit token from a byte array
     * <p>
     * This checks the signature, but does not verify that the first key is the root key,
     * to allow appending blocks without knowing about the root key.
     * <p>
     * The root key check is performed in the verify method
     *
     * @param data
     * @return
     */
    static public Biscuit fromBytesWithSymbols(byte[] data, KeyDelegate delegate, SymbolTable symbols) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        //System.out.println("will deserialize and verify token");
        SerializedBiscuit ser = SerializedBiscuit.fromBytes(data, delegate);
        //System.out.println("deserialized token, will populate Biscuit structure");

        return Biscuit.fromSerializedBiscuit(ser, symbols);
    }

    /**
     * Fills a Biscuit structure from a deserialized token
     *
     * @return
     */
    static Biscuit fromSerializedBiscuit(SerializedBiscuit ser, SymbolTable symbols) throws Error {
        Tuple2<Block, ArrayList<Block>> t = ser.extractBlocks(symbols);
        Block authority = t._1;
        ArrayList<Block> blocks = t._2;

        List<byte[]> revocationIds = ser.revocationIdentifiers();

        return new Biscuit(authority, blocks, symbols, ser, revocationIds);
    }

    /**
     * Creates a authorizer for this token
     * <p>
     * This function checks that the root key is the one we expect
     *
     * @return
     */
    public Authorizer authorizer() throws Error.FailedLogic {
        return Authorizer.make(this);
    }

    /**
     * Serializes a token to a byte array
     *
     * @return
     */
    public byte[] serialize() throws Error.FormatError.SerializationError {
        return this.serializedBiscuit.serialize();
    }

    /**
     * Serializes a token to base 64 url String using RFC4648_URLSAFE
     *
     * @return String
     * @throws Error.FormatError.SerializationError
     */
    public String serializeBase64Url() throws Error.FormatError.SerializationError {
        return Base64.getUrlEncoder().encodeToString(serialize());
    }

    /**
     * Generates a new token from an existing one and a new block
     *
     * @param block new block (should be generated from a Block builder)
     * @param algorithm algorithm to use for the ephemeral key pair
     * @return
     */
    public Biscuit attenuate(org.biscuitsec.biscuit.token.builder.Block block, Algorithm algorithm) throws Error {
        SecureRandom rng = new SecureRandom();
        KeyPair keypair = KeyPair.generate(algorithm, rng);
        SymbolTable builderSymbols = new SymbolTable(this.symbols);
        return attenuate(rng, keypair, block.build(builderSymbols));
    }

    public Biscuit attenuate(final SecureRandom rng, final KeyPair keypair, org.biscuitsec.biscuit.token.builder.Block block) throws Error {
        SymbolTable builderSymbols = new SymbolTable(this.symbols);
        return attenuate(rng, keypair, block.build(builderSymbols));
    }

    /**
     * Generates a new token from an existing one and a new block
     *
     * @param rng     random number generator
     * @param keypair ephemeral key pair
     * @param block   new block (should be generated from a Block builder)
     * @return
     */
    public Biscuit attenuate(final SecureRandom rng, final KeyPair keypair, Block block) throws Error {
        Biscuit copiedBiscuit = this.copy();

        if (!Collections.disjoint(copiedBiscuit.symbols.symbols, block.symbols.symbols)) {
            throw new Error.SymbolTableOverlap();
        }

        Either<Error.FormatError, SerializedBiscuit> containerRes = copiedBiscuit.serializedBiscuit.append(keypair, block, Option.none());
        if (containerRes.isLeft()) {
            throw containerRes.getLeft();
        }
        SerializedBiscuit container = containerRes.get();

        SymbolTable symbols = new SymbolTable(copiedBiscuit.symbols);
        for (String s : block.symbols.symbols) {
            symbols.add(s);
        }

        for(PublicKey pk: block.publicKeys) {
            symbols.insert(pk);
        }

        ArrayList<Block> blocks = new ArrayList<>();
        for (Block b : copiedBiscuit.blocks) {
            blocks.add(b);
        }
        blocks.add(block);

        List<byte[]> revocationIds = container.revocationIdentifiers();

        return new Biscuit(copiedBiscuit.authority, blocks, symbols, container, revocationIds);
    }

    /**
     * Generates a third party block request from a token
     */
    public Biscuit appendThirdPartyBlock(PublicKey externalKey, ThirdPartyBlockContents blockResponse)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
       UnverifiedBiscuit b = super.appendThirdPartyBlock(externalKey, blockResponse);

       // no need to verify again, we are already working from a verified token
        return Biscuit.fromSerializedBiscuit(b.serializedBiscuit, b.symbols);
    }

    /**
     * Prints a token's content
     */
    public String print() {
        StringBuilder s = new StringBuilder();
        s.append("Biscuit {\n\tsymbols: ");
        s.append(this.symbols.getAllSymbols());
        s.append("\n\tpublic keys: ");
        s.append(this.symbols.getPublicKeys());
        s.append("\n\tauthority: ");
        s.append(this.authority.print(this.symbols));
        s.append("\n\tblocks: [\n");
        for (Block b : this.blocks) {
            s.append("\t\t");
            if(b.externalKey.isDefined()) {
                s.append(b.print(b.symbols));
            } else {
                s.append(b.print(this.symbols));
            }
            s.append("\n");
        }
        s.append("\t]\n}");

        return s.toString();
    }

    public Biscuit copy() throws Error {
        return Biscuit.fromSerializedBiscuit(this.serializedBiscuit, this.symbols);
    }
}
