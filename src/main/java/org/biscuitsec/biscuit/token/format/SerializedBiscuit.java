package org.biscuitsec.biscuit.token.format;

import biscuit.format.schema.Schema;
import io.vavr.Tuple2;
import org.biscuitsec.biscuit.crypto.BlockSignatureBuffer;
import org.biscuitsec.biscuit.crypto.KeyDelegate;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Block;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.vavr.control.Either;
import io.vavr.control.Option;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;


import static io.vavr.API.Left;
import static io.vavr.API.Right;

/**
 * Intermediate representation of a token before full serialization
 */
public final class SerializedBiscuit {
    private final SignedBlock authority;
    private final List<SignedBlock> blocks;
    private Proof proof;
    private Option<Integer> rootKeyId;

    public static final int MIN_SCHEMA_VERSION = 3;
    public static final int MAX_SCHEMA_VERSION = 5;

    /**
     * Deserializes a SerializedBiscuit from a byte array
     *
     * @param slice
     * @return
     */
    public static SerializedBiscuit fromBytes(byte[] slice, org.biscuitsec.biscuit.crypto.PublicKey root) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        try {
            Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);

            return fromBytesInner(data, root);
        } catch (InvalidProtocolBufferException e) {
            throw new Error.FormatError.DeserializationError(e.toString());
        }
    }

    /**
     * Deserializes a SerializedBiscuit from a byte array
     *
     * @param slice
     * @return
     */
    public static SerializedBiscuit fromBytes(byte[] slice, KeyDelegate delegate) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        try {
            Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);

            Option<Integer> rootKeyId = Option.none();
            if (data.hasRootKeyId()) {
                rootKeyId = Option.some(data.getRootKeyId());
            }

            Option<org.biscuitsec.biscuit.crypto.PublicKey> root = delegate.getRootKey(rootKeyId);
            if (root.isEmpty()) {
                throw new InvalidKeyException("unknown root key id");
            }

            return fromBytesInner(data, root.get());
        } catch (InvalidProtocolBufferException e) {
            throw new Error.FormatError.DeserializationError(e.toString());
        }
    }

    static SerializedBiscuit fromBytesInner(Schema.Biscuit data, org.biscuitsec.biscuit.crypto.PublicKey root) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        SerializedBiscuit b = SerializedBiscuit.deserialize(data);
        if (data.hasRootKeyId()) {
            b.rootKeyId = Option.some(data.getRootKeyId());
        }

        Either<Error, Void> res = b.verify(root);
        if (res.isLeft()) {
            throw res.getLeft();
        } else {
            return b;
        }

    }

    /**
     * Warning: this deserializes without verifying the signature
     *
     * @param slice
     * @return SerializedBiscuit
     * @throws Error.FormatError.DeserializationError
     */
    public static SerializedBiscuit deserializeUnsafe(byte[] slice) throws Error.FormatError.DeserializationError {
        try {
            Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);
            return SerializedBiscuit.deserialize(data);
        } catch (InvalidProtocolBufferException e) {
            throw new Error.FormatError.DeserializationError(e.toString());
        }
    }

    /**
     * Warning: this deserializes without verifying the signature
     *
     * @param data
     * @return SerializedBiscuit
     * @throws Error.FormatError.DeserializationError
     */
    private static SerializedBiscuit deserialize(Schema.Biscuit data) throws Error.FormatError.DeserializationError {
        if (data.getAuthority().hasExternalSignature()) {
            throw new Error.FormatError.DeserializationError("the authority block must not contain an external signature");
        }

        SignedBlock authority = new SignedBlock(
                data.getAuthority().getBlock().toByteArray(),
                org.biscuitsec.biscuit.crypto.PublicKey.deserialize(data.getAuthority().getNextKey()),
                data.getAuthority().getSignature().toByteArray(),
                Option.none()
        );

        ArrayList<SignedBlock> blocks = new ArrayList<>();
        for (Schema.SignedBlock block : data.getBlocksList()) {
            Option<ExternalSignature> external = Option.none();
            if (block.hasExternalSignature() && block.getExternalSignature().hasPublicKey()
                && block.getExternalSignature().hasSignature()) {
                Schema.ExternalSignature ex = block.getExternalSignature();
                external = Option.some(new ExternalSignature(
                        org.biscuitsec.biscuit.crypto.PublicKey.deserialize(ex.getPublicKey()),
                        ex.getSignature().toByteArray()));

            }
            blocks.add(new SignedBlock(
                    block.getBlock().toByteArray(),
                    org.biscuitsec.biscuit.crypto.PublicKey.deserialize(block.getNextKey()),
                    block.getSignature().toByteArray(),
                    external
            ));
        }

        if (!(data.getProof().hasNextSecret() ^ data.getProof().hasFinalSignature())) {
            throw new Error.FormatError.DeserializationError("empty proof");
        }

        final Proof proof = data.getProof().hasFinalSignature()
               ? new Proof.FinalSignature(data.getProof().getFinalSignature().toByteArray())
                : new Proof.NextSecret(KeyPair.generate(authority.getKey().getAlgorithm(),
                        data.getProof().getNextSecret().toByteArray()));

        Option<Integer> rootKeyId = data.hasRootKeyId() ? Option.some(data.getRootKeyId()) : Option.none();

        return new SerializedBiscuit(authority, blocks, proof, rootKeyId);
    }


    /**
     * Serializes a SerializedBiscuit to a byte array
     *
     * @return
     */
    public byte[] serialize() throws Error.FormatError.SerializationError {
        Schema.Biscuit.Builder biscuitBuilder = Schema.Biscuit.newBuilder();
        Schema.SignedBlock.Builder authorityBuilder = Schema.SignedBlock.newBuilder();
        SignedBlock authorityBlock = this.authority;
        authorityBuilder.setBlock(ByteString.copyFrom(authorityBlock.getBlock()));
        authorityBuilder.setNextKey(authorityBlock.getKey().serialize());
        authorityBuilder.setSignature(ByteString.copyFrom(authorityBlock.getSignature()));
        biscuitBuilder.setAuthority(authorityBuilder.build());

        for (SignedBlock b : this.blocks) {
            Schema.SignedBlock.Builder blockBuilder = Schema.SignedBlock.newBuilder();
            blockBuilder.setBlock(ByteString.copyFrom(b.getBlock()));
            blockBuilder.setNextKey(b.getKey().serialize());
            blockBuilder.setSignature(ByteString.copyFrom(b.getSignature()));

            if (b.getExternalSignature().isDefined()) {
                ExternalSignature externalSignature = b.getExternalSignature().get();
                Schema.ExternalSignature.Builder externalSignatureBuilder = Schema.ExternalSignature.newBuilder();
                externalSignatureBuilder.setPublicKey(externalSignature.getKey().serialize());
                externalSignatureBuilder.setSignature(ByteString.copyFrom(externalSignature.getSignature()));
                blockBuilder.setExternalSignature(externalSignatureBuilder.build());
            }

            biscuitBuilder.addBlocks(blockBuilder.build());
        }

        Schema.Proof.Builder proofBuilder = Schema.Proof.newBuilder();
        if (this.proof.isSealed()) {
            Proof.FinalSignature finalSignature = (Proof.FinalSignature) this.proof;
            proofBuilder.setFinalSignature(ByteString.copyFrom(finalSignature.signature()));
        } else {
            Proof.NextSecret nextSecret = (Proof.NextSecret) this.proof;
            proofBuilder.setNextSecret(ByteString.copyFrom(nextSecret.secretKey().toBytes()));
        }

        biscuitBuilder.setProof(proofBuilder.build());
        if (!this.rootKeyId.isEmpty()) {
            biscuitBuilder.setRootKeyId(this.rootKeyId.get());
        }

        Schema.Biscuit biscuit = biscuitBuilder.build();

        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            biscuit.writeTo(stream);
            return stream.toByteArray();
        } catch (IOException e) {
            throw new Error.FormatError.SerializationError(e.toString());
        }

    }

    public static Either<Error.FormatError, SerializedBiscuit> make(final org.biscuitsec.biscuit.crypto.KeyPair root,
                                                                    final Block authority, final org.biscuitsec.biscuit.crypto.KeyPair next) {

        return make(root, Option.none(), authority, next);
    }

    public static Either<Error.FormatError, SerializedBiscuit> make(final org.biscuitsec.biscuit.crypto.Signer rootSigner, final Option<Integer> rootKeyId,
                                                                    final Block authority, final org.biscuitsec.biscuit.crypto.KeyPair next) {
        Schema.Block b = authority.serialize();
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            b.writeTo(stream);
            byte[] block = stream.toByteArray();
            org.biscuitsec.biscuit.crypto.PublicKey nextKey = next.getPublicKey();
            byte[] payload = BlockSignatureBuffer.getBufferSignature(nextKey, block);
            byte[] signature = rootSigner.sign(payload);
            SignedBlock signedBlock = new SignedBlock(block, nextKey, signature, Option.none());
            Proof proof = new Proof.NextSecret(next);

            return Right(new SerializedBiscuit(signedBlock, new ArrayList<>(), proof, rootKeyId));
        } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            return Left(new Error.FormatError.SerializationError(e.toString()));
        }
    }

    public Either<Error.FormatError, SerializedBiscuit> append(final org.biscuitsec.biscuit.crypto.KeyPair next,
                                                               final Block newBlock, Option<ExternalSignature> externalSignature) {
        if (this.proof.isSealed()) {
            return Left(new Error.FormatError.SerializationError("the token is sealed"));
        }

        Schema.Block b = newBlock.serialize();
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            b.writeTo(stream);

            byte[] block = stream.toByteArray();
            KeyPair secretKey = this.proof.secretKey();
            org.biscuitsec.biscuit.crypto.PublicKey nextKey = next.getPublicKey();

            byte[] payload = BlockSignatureBuffer.getBufferSignature(nextKey, block, externalSignature.toJavaOptional());
            byte[] signature = this.proof.secretKey().sign(payload);

            SignedBlock signedBlock = new SignedBlock(block, nextKey, signature, externalSignature);

            ArrayList<SignedBlock> blocks = new ArrayList<>();
            for (SignedBlock bl : this.blocks) {
                blocks.add(bl);
            }
            blocks.add(signedBlock);

            Proof proof = new Proof.NextSecret(next);

            return Right(new SerializedBiscuit(this.authority, blocks, proof, rootKeyId));
        } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            return Left(new Error.FormatError.SerializationError(e.toString()));
        }
    }

    public Either<Error, Void> verify(org.biscuitsec.biscuit.crypto.PublicKey root) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        org.biscuitsec.biscuit.crypto.PublicKey currentKey = root;
        Either<Error, org.biscuitsec.biscuit.crypto.PublicKey> res = verifyBlockSignature(this.authority, currentKey);
        if (res.isRight()) {
            currentKey = res.get();
        } else {
            return Left(res.getLeft());
        }

        for (SignedBlock b : this.blocks) {
            res = verifyBlockSignature(b, currentKey);
            if (res.isRight()) {
                currentKey = res.get();
            } else {
                return Left(res.getLeft());
            }
        }

        //System.out.println("signatures verified, checking proof");

        if (!this.proof.isSealed()) {
            //System.out.println("checking secret key");
            //System.out.println("current key: "+currentKey.toHex());
            //System.out.println("key from proof: "+this.proof.secretKey.get().public_key().toHex());
            if (this.proof.secretKey().getPublicKey().equals(currentKey)) {
                //System.out.println("public keys are equal");

                return Right(null);
            } else {
                //System.out.println("public keys are not equal");

                return Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied"));
            }
        } else {
            //System.out.println("checking final signature");

            byte[] finalSignature = this.proof.getSignature().get();

            SignedBlock b;
            if (this.blocks.isEmpty()) {
                b = this.authority;
            } else {
                b = this.blocks.get(this.blocks.size() - 1);
            }

            byte[] block = b.getBlock();
            org.biscuitsec.biscuit.crypto.PublicKey nextKey = b.getKey();
            byte[] signature = b.getSignature();

            byte[] payload = BlockSignatureBuffer.getBufferSealedSignature(nextKey, block, signature);

            if (KeyPair.verify(currentKey, payload, finalSignature)) {
                return Right(null);
            } else {
                return Left(new Error.FormatError.Signature.SealedSignature());
            }

        }
    }

    static Either<Error, org.biscuitsec.biscuit.crypto.PublicKey> verifyBlockSignature(SignedBlock signedBlock, org.biscuitsec.biscuit.crypto.PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] block = signedBlock.getBlock();
        org.biscuitsec.biscuit.crypto.PublicKey nextKey = signedBlock.getKey();
        byte[] signature = signedBlock.getSignature();

        var signatureLengthError = PublicKey.validateSignatureLength(publicKey.getAlgorithm(), signature.length);
        if (signatureLengthError.isPresent()) {
            return Left(signatureLengthError.get());
        }

        ByteBuffer algoBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        algoBuf.putInt(Integer.valueOf(nextKey.getAlgorithm().getNumber()));
        algoBuf.flip();

        Signature sgr = KeyPair.generateSignature(publicKey.getAlgorithm());
        sgr.initVerify(publicKey.getKey());
        sgr.update(block);
        if (signedBlock.getExternalSignature().isDefined()) {
            sgr.update(signedBlock.getExternalSignature().get().getSignature());
        }
        sgr.update(algoBuf);
        sgr.update(nextKey.toBytes());
        byte[] payload = BlockSignatureBuffer.getBufferSignature(nextKey, block, signedBlock.getExternalSignature().toJavaOptional());
        if (!KeyPair.verify(publicKey, payload, signature)) {
            return Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied"));
        }

        if (signedBlock.getExternalSignature().isDefined()) {
            byte[] externalPayload = BlockSignatureBuffer.getBufferSignature(publicKey, block);
            ExternalSignature externalSignature = signedBlock.getExternalSignature().get();

            if (!KeyPair.verify(externalSignature.getKey(), externalPayload, externalSignature.getSignature())) {
                return Left(new Error.FormatError.Signature.InvalidSignature("external signature error: Verification equation was not satisfied"));
            }
        }

        return Right(nextKey);
    }

    public Tuple2<Block, ArrayList<Block>> extractBlocks(SymbolTable symbols) throws Error {
        ArrayList<Option<org.biscuitsec.biscuit.crypto.PublicKey>> blockExternalKeys = new ArrayList<>();
        Either<Error.FormatError, Block> authRes = Block.fromBytes(this.authority.getBlock(), Option.none());
        if (authRes.isLeft()) {
            throw authRes.getLeft();
        }
        Block authority = authRes.get();
        for (org.biscuitsec.biscuit.crypto.PublicKey pk: authority.publicKeys()) {
            symbols.insert(pk);
        }
        blockExternalKeys.add(Option.none());

        for (String s : authority.symbols().symbols()) {
            symbols.add(s);
        }

        ArrayList<Block> blocks = new ArrayList<>();
        for (SignedBlock bdata : this.blocks) {
            Option<org.biscuitsec.biscuit.crypto.PublicKey> externalKey = Option.none();
            if (bdata.getExternalSignature().isDefined()) {
                externalKey = Option.some(bdata.getExternalSignature().get().getKey());
            }
            Either<Error.FormatError, Block> blockRes = Block.fromBytes(bdata.getBlock(), externalKey);
            if (blockRes.isLeft()) {
                throw blockRes.getLeft();
            }
            Block block = blockRes.get();

            // blocks with external signatures keep their own symbol table
            if (bdata.getExternalSignature().isDefined()) {
                //symbols.insert(bdata.externalSignature.get().key);
                blockExternalKeys.add(Option.some(bdata.getExternalSignature().get().getKey()));
            } else {
                blockExternalKeys.add(Option.none());
                for (String s : block.symbols().symbols()) {
                    symbols.add(s);
                }
                for (org.biscuitsec.biscuit.crypto.PublicKey pk: block.publicKeys()) {
                    symbols.insert(pk);
                }
            }

            blocks.add(block);
        }

        return new Tuple2<>(authority, blocks);
    }

    public Either<Error, Void> seal() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        if (this.proof.isSealed()) {
            return Left(new Error.Sealed());
        }

        SignedBlock block;
        if (this.blocks.isEmpty()) {
            block = this.authority;
        } else {
            block = this.blocks.get(this.blocks.size() - 1);
        }

        KeyPair secretKey = ((Proof.NextSecret) this.proof).secretKey();
        byte[] payload = BlockSignatureBuffer.getBufferSealedSignature(block.getKey(), block.getBlock(), block.getSignature());
        byte[] signature = secretKey.sign(payload);

        this.proof = new Proof.FinalSignature(signature);

        return Right(null);
    }

    public List<byte[]> revocationIdentifiers() {
        ArrayList<byte[]> l = new ArrayList<>();
        l.add(this.authority.getSignature());

        for (SignedBlock block : this.blocks) {
            l.add(block.getSignature());
        }
        return l;
    }

    SerializedBiscuit(SignedBlock authority, List<SignedBlock> blocks, Proof proof) {
        this.authority = authority;
        this.blocks = blocks;
        this.proof = proof;
        this.rootKeyId = Option.none();
    }

    SerializedBiscuit(SignedBlock authority, List<SignedBlock> blocks, Proof proof, Option<Integer> rootKeyId) {
        this.authority = authority;
        this.blocks = blocks;
        this.proof = proof;
        this.rootKeyId = rootKeyId;
    }

    public SignedBlock getAuthority() {
        return authority;
    }

    public List<SignedBlock> getBlocks() {
        return blocks;
    }

    public Proof getProof() {
        return proof;
    }

    public Option<Integer> getRootKeyId() {
        return rootKeyId;
    }
}
