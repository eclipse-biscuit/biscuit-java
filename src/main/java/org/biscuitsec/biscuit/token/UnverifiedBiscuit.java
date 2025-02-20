package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import org.biscuitsec.biscuit.crypto.BlockSignatureBuffer;
import org.biscuitsec.biscuit.crypto.KeyDelegate;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.format.ExternalSignature;
import org.biscuitsec.biscuit.token.format.SerializedBiscuit;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import io.vavr.control.Option;
import org.biscuitsec.biscuit.datalog.Check;
import org.biscuitsec.biscuit.datalog.SymbolTable;

import java.security.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * UnverifiedBiscuit auth token. UnverifiedBiscuit means it's deserialized without checking signatures.
 */
public class UnverifiedBiscuit {
    final Block authority;
    final List<Block> blocks;
    final SymbolTable symbols;
    final SerializedBiscuit serializedBiscuit;
    final List<byte[]> revocationIds;

    UnverifiedBiscuit(Block authority, List<Block> blocks, SymbolTable symbols, SerializedBiscuit serializedBiscuit,
                       List<byte[]> revocationIds) {
        this.authority = authority;
        this.blocks = blocks;
        this.symbols = symbols;
        this.serializedBiscuit = serializedBiscuit;
        this.revocationIds = revocationIds;
    }

    /**
     * Deserializes a Biscuit token from a base64 url (RFC4648_URLSAFE) string
     * <p>
     * This method uses the default symbol table
     *
     * @param data
     * @return Biscuit
     */
    static public UnverifiedBiscuit from_b64url(String data) throws Error {
        return UnverifiedBiscuit.from_bytes(Base64.getUrlDecoder().decode(data));
    }

    /**
     * Deserializes a Biscuit token from a byte array
     * <p>
     * This method uses the default symbol table
     *
     * @param data
     * @return
     */
    static public UnverifiedBiscuit from_bytes(byte[] data) throws Error {
        return UnverifiedBiscuit.from_bytes_with_symbols(data, default_symbol_table());
    }

    /**
     * Deserializes a UnverifiedBiscuit from a byte array
     *
     * @param data
     * @return UnverifiedBiscuit
     */
    static public UnverifiedBiscuit from_bytes_with_symbols(byte[] data, SymbolTable symbols) throws Error {
        SerializedBiscuit ser = SerializedBiscuit.unsafe_deserialize(data);
        return UnverifiedBiscuit.from_serialized_biscuit(ser, symbols);
    }

    /**
     * Fills a UnverifiedBiscuit structure from a deserialized token
     *
     * @return UnverifiedBiscuit
     */
    static private UnverifiedBiscuit from_serialized_biscuit(SerializedBiscuit ser, SymbolTable symbols) throws Error {
        Tuple2<Block, ArrayList<Block>> t = ser.extractBlocks(symbols);
        Block authority = t._1;
        ArrayList<Block> blocks = t._2;

        List<byte[]> revocation_ids = ser.revocationIdentifiers();

        return new UnverifiedBiscuit(authority, blocks, symbols, ser, revocation_ids);
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
    public String serialize_b64url() throws Error.FormatError.SerializationError {
        return Base64.getUrlEncoder().encodeToString(serialize());
    }

    /**
     * Creates a Block builder
     *
     * @return
     */
    public org.biscuitsec.biscuit.token.builder.Block create_block() {
        return new org.biscuitsec.biscuit.token.builder.Block();
    }

    /**
     * Generates a new token from an existing one and a new block
     *
     * @param block new block (should be generated from a Block builder)
     * @param algorithm algorithm to use for the ephemeral key pair
     * @return
     */
    public UnverifiedBiscuit attenuate(org.biscuitsec.biscuit.token.builder.Block block, Algorithm algorithm) throws Error {
        SecureRandom rng = new SecureRandom();
        KeyPair keypair = KeyPair.generate(algorithm, rng);
        SymbolTable builderSymbols = new SymbolTable(this.symbols);
        return attenuate(rng, keypair, block.build(builderSymbols));
    }

    public UnverifiedBiscuit attenuate(final SecureRandom rng, final KeyPair keypair, org.biscuitsec.biscuit.token.builder.Block block) throws Error {
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
    public UnverifiedBiscuit attenuate(final SecureRandom rng, final KeyPair keypair, Block block) throws Error {
        UnverifiedBiscuit copiedBiscuit = this.copy();

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

        ArrayList<Block> blocks = new ArrayList<>();
        for (Block b : copiedBiscuit.blocks) {
            blocks.add(b);
        }
        blocks.add(block);

        List<byte[]> revocation_ids = container.revocationIdentifiers();

        return new UnverifiedBiscuit(copiedBiscuit.authority, blocks, symbols, container, revocation_ids);
    }
    //FIXME: attenuate 3rd Party

    public List<RevocationIdentifier> revocation_identifiers() {
        return this.revocationIds.stream()
                .map(RevocationIdentifier::from_bytes)
                .collect(Collectors.toList());
    }

    public List<List<Check>> checks() {
        ArrayList<List<Check>> l = new ArrayList<>();
        l.add(new ArrayList<>(this.authority.checks));

        for (Block b : this.blocks) {
            l.add(new ArrayList<>(b.checks));
        }

        return l;
    }

    public List<Option<String>> context() {
        ArrayList<Option<String>> res = new ArrayList<>();
        if (this.authority.context.isEmpty()) {
            res.add(Option.none());
        } else {
            res.add(Option.some(this.authority.context));
        }

        for (Block b : this.blocks) {
            if (b.context.isEmpty()) {
                res.add(Option.none());
            } else {
                res.add(Option.some(b.context));
            }
        }

        return res;
    }

    public Option<Integer> root_key_id() {
        return this.serializedBiscuit.rootKeyId;
    }

    /**
     * Generates a third party block request from a token
     */
    public ThirdPartyBlockRequest thirdPartyRequest() {
        PublicKey previousKey;
        if(this.serializedBiscuit.blocks.isEmpty()) {
            previousKey = this.serializedBiscuit.authority.key;
        } else {
            previousKey = this.serializedBiscuit.blocks.get(this.serializedBiscuit.blocks.size() - 1).key;
        }

        return new ThirdPartyBlockRequest(previousKey);
    }


    /**
     * Generates a third party block request from a token
     */
    public UnverifiedBiscuit appendThirdPartyBlock(PublicKey externalKey, ThirdPartyBlockContents blockResponse)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        PublicKey previousKey;
        if(this.serializedBiscuit.blocks.isEmpty()) {
            previousKey = this.serializedBiscuit.authority.key;
        } else {
            previousKey = this.serializedBiscuit.blocks.get(this.serializedBiscuit.blocks.size() - 1).key;
        }
        KeyPair nextKeyPair = KeyPair.generate(previousKey.algorithm);
        byte[] payload = BlockSignatureBuffer.getBufferSignature(previousKey, blockResponse.payload);
        if (!KeyPair.verify(externalKey, payload, blockResponse.signature)) {
            throw new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied");
        }

        Either<Error.FormatError, Block> res = Block.from_bytes(blockResponse.payload, Option.some(externalKey));
        if(res.isLeft()) {
            throw res.getLeft();
        }

        Block block = res.get();

        ExternalSignature externalSignature = new ExternalSignature(externalKey, blockResponse.signature);

        UnverifiedBiscuit copiedBiscuit = this.copy();

        Either<Error.FormatError, SerializedBiscuit> containerRes = copiedBiscuit.serializedBiscuit.append(nextKeyPair, block, Option.some(externalSignature));
        if (containerRes.isLeft()) {
            throw containerRes.getLeft();
        }

        SerializedBiscuit container = containerRes.get();

        SymbolTable symbols = new SymbolTable(copiedBiscuit.symbols);

        ArrayList<Block> blocks = new ArrayList<>();
        for (Block b : copiedBiscuit.blocks) {
            blocks.add(b);
        }
        blocks.add(block);

        List<byte[]> revocation_ids = container.revocationIdentifiers();
        return new UnverifiedBiscuit(copiedBiscuit.authority, blocks, symbols, container, revocation_ids);
    }

    /**
     * Prints a token's content
     */
    public String print() {
        StringBuilder s = new StringBuilder();
        s.append("UnverifiedBiscuit {\n\tsymbols: ");
        s.append(this.symbols.getAllSymbols());
        s.append("\n\tauthority: ");
        s.append(this.authority.print(this.symbols));
        s.append("\n\tblocks: [\n");
        for (Block b : this.blocks) {
            s.append("\t\t");
            s.append(b.print(this.symbols));
            s.append("\n");
        }
        s.append("\t]\n}");

        return s.toString();
    }

    /**
     * Default symbols list
     */
    static public SymbolTable default_symbol_table() {
        return new SymbolTable();
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    public UnverifiedBiscuit copy() throws Error {
        return UnverifiedBiscuit.from_bytes(this.serialize());
    }

    public Biscuit verify(PublicKey publicKey) throws Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SerializedBiscuit serializedBiscuit = this.serializedBiscuit;
        var result = serializedBiscuit.verify(publicKey);
        if (result.isLeft()) {
            throw result.getLeft();
        }
        return Biscuit.from_serialized_biscuit(serializedBiscuit, this.symbols);
    }

    public Biscuit verify(KeyDelegate delegate) throws Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SerializedBiscuit serializedBiscuit = this.serializedBiscuit;

        Option<PublicKey> root = delegate.root_key(serializedBiscuit.rootKeyId);
        if(root.isEmpty()) {
            throw new InvalidKeyException("unknown root key id");
        }

        var result = serializedBiscuit.verify(root.get());
        if (result.isLeft()) {
            throw result.getLeft();
        }
        return Biscuit.from_serialized_biscuit(serializedBiscuit, this.symbols);
    }
}
