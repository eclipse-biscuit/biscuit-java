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
import java.security.*;
import java.util.*;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

/**
 * Intermediate representation of a token before full serialization
 */
public class SerializedBiscuit {
    public SignedBlock authority;
    public List<SignedBlock> blocks;
    public Proof proof;
    public Option<Integer> root_key_id;

    public final static int MIN_SCHEMA_VERSION = 3;
    public final static int MAX_SCHEMA_VERSION = 5;

    /**
     * Deserializes a SerializedBiscuit from a byte array
     *
     * @param slice
     * @return
     */
    static public SerializedBiscuit from_bytes(byte[] slice, org.biscuitsec.biscuit.crypto.PublicKey root) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        try {
            Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);

            return from_bytes_inner(data, root);
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
    static public SerializedBiscuit from_bytes(byte[] slice, KeyDelegate delegate) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        try {
            Schema.Biscuit data = Schema.Biscuit.parseFrom(slice);

            Option<Integer> root_key_id = Option.none();
            if (data.hasRootKeyId()) {
                root_key_id = Option.some(data.getRootKeyId());
            }

            Option<org.biscuitsec.biscuit.crypto.PublicKey> root = delegate.root_key(root_key_id);
            if (root.isEmpty()) {
                throw new InvalidKeyException("unknown root key id");
            }

            return from_bytes_inner(data, root.get());
        } catch (InvalidProtocolBufferException e) {
            throw new Error.FormatError.DeserializationError(e.toString());
        }
    }

    static SerializedBiscuit from_bytes_inner(Schema.Biscuit data, org.biscuitsec.biscuit.crypto.PublicKey root) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        SerializedBiscuit b = SerializedBiscuit.deserialize(data);
        if (data.hasRootKeyId()) {
            b.root_key_id = Option.some(data.getRootKeyId());
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
    static public SerializedBiscuit unsafe_deserialize(byte[] slice) throws Error.FormatError.DeserializationError {
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
    static private SerializedBiscuit deserialize(Schema.Biscuit data) throws Error.FormatError.DeserializationError {
        if(data.getAuthority().hasExternalSignature()) {
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
            if(block.hasExternalSignature() && block.getExternalSignature().hasPublicKey()
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

        Option<org.biscuitsec.biscuit.crypto.KeyPair> secretKey = Option.none();
        if (data.getProof().hasNextSecret()) {
            secretKey = Option.some(KeyPair.generate(authority.key.algorithm, data.getProof().getNextSecret().toByteArray()));
        }

        Option<byte[]> signature = Option.none();
        if (data.getProof().hasFinalSignature()) {
            signature = Option.some(data.getProof().getFinalSignature().toByteArray());
        }

        if (secretKey.isEmpty() && signature.isEmpty()) {
            throw new Error.FormatError.DeserializationError("empty proof");
        }
        Proof proof = new Proof(secretKey, signature);

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
        authorityBuilder.setBlock(ByteString.copyFrom(authorityBlock.block));
        authorityBuilder.setNextKey(authorityBlock.key.serialize());
        authorityBuilder.setSignature(ByteString.copyFrom(authorityBlock.signature));
        biscuitBuilder.setAuthority(authorityBuilder.build());

        for (SignedBlock b : this.blocks) {
            Schema.SignedBlock.Builder blockBuilder = Schema.SignedBlock.newBuilder();
            blockBuilder.setBlock(ByteString.copyFrom(b.block));
            blockBuilder.setNextKey(b.key.serialize());
            blockBuilder.setSignature(ByteString.copyFrom(b.signature));

            if (b.externalSignature.isDefined()) {
                ExternalSignature externalSignature = b.externalSignature.get();
                Schema.ExternalSignature.Builder externalSignatureBuilder = Schema.ExternalSignature.newBuilder();
                externalSignatureBuilder.setPublicKey(externalSignature.key.serialize());
                externalSignatureBuilder.setSignature(ByteString.copyFrom(externalSignature.signature));
                blockBuilder.setExternalSignature(externalSignatureBuilder.build());
            }

            biscuitBuilder.addBlocks(blockBuilder.build());
        }

        Schema.Proof.Builder proofBuilder = Schema.Proof.newBuilder();
        if (!this.proof.secretKey.isEmpty()) {
            proofBuilder.setNextSecret(ByteString.copyFrom(this.proof.secretKey.get().toBytes()));
        } else {
            proofBuilder.setFinalSignature(ByteString.copyFrom(this.proof.signature.get()));
        }

        biscuitBuilder.setProof(proofBuilder.build());
        if (!this.root_key_id.isEmpty()) {
            biscuitBuilder.setRootKeyId(this.root_key_id.get());
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

    static public Either<Error.FormatError, SerializedBiscuit> make(final org.biscuitsec.biscuit.crypto.KeyPair root,
                                                                    final Block authority, final org.biscuitsec.biscuit.crypto.KeyPair next) {

        return make(root, Option.none(), authority, next);
    }

    static public Either<Error.FormatError, SerializedBiscuit> make(final org.biscuitsec.biscuit.crypto.Signer rootSigner, final Option<Integer> root_key_id,
                                                                    final Block authority, final org.biscuitsec.biscuit.crypto.KeyPair next) {
        Schema.Block b = authority.serialize();
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            b.writeTo(stream);
            byte[] block = stream.toByteArray();
            org.biscuitsec.biscuit.crypto.PublicKey next_key = next.public_key();
            byte[] payload = BlockSignatureBuffer.getBufferSignature(next_key, block);
            byte[] signature = rootSigner.sign(payload);
            SignedBlock signedBlock = new SignedBlock(block, next_key, signature, Option.none());
            Proof proof = new Proof(next);

            return Right(new SerializedBiscuit(signedBlock, new ArrayList<>(), proof, root_key_id));
        } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            return Left(new Error.FormatError.SerializationError(e.toString()));
        }
    }

    public Either<Error.FormatError, SerializedBiscuit> append(final org.biscuitsec.biscuit.crypto.KeyPair next,
                                                               final Block newBlock, Option<ExternalSignature> externalSignature) {
        if (this.proof.secretKey.isEmpty()) {
            return Left(new Error.FormatError.SerializationError("the token is sealed"));
        }

        Schema.Block b = newBlock.serialize();
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            b.writeTo(stream);

            byte[] block = stream.toByteArray();
            KeyPair secretKey = this.proof.secretKey.get();
            org.biscuitsec.biscuit.crypto.PublicKey next_key = next.public_key();

            byte[] payload = BlockSignatureBuffer.getBufferSignature(next_key, block, externalSignature.toJavaOptional());
            byte[] signature = this.proof.secretKey.get().sign(payload);

            SignedBlock signedBlock = new SignedBlock(block, next_key, signature, externalSignature);

            ArrayList<SignedBlock> blocks = new ArrayList<>();
            for (SignedBlock bl : this.blocks) {
                blocks.add(bl);
            }
            blocks.add(signedBlock);

            Proof proof = new Proof(next);

            return Right(new SerializedBiscuit(this.authority, blocks, proof, root_key_id));
        } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            return Left(new Error.FormatError.SerializationError(e.toString()));
        }
    }

    public Either<Error, Void> verify(org.biscuitsec.biscuit.crypto.PublicKey root) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        org.biscuitsec.biscuit.crypto.PublicKey current_key = root;
        Either<Error, org.biscuitsec.biscuit.crypto.PublicKey> res = verifyBlockSignature(this.authority, current_key);
        if(res.isRight()) {
            current_key = res.get();
        } else {
            return Left(res.getLeft());
        }

        for (SignedBlock b : this.blocks) {
            res = verifyBlockSignature(b, current_key);
            if(res.isRight()) {
                current_key = res.get();
            } else {
                return Left(res.getLeft());
            }
        }

        //System.out.println("signatures verified, checking proof");

        if (!this.proof.secretKey.isEmpty()) {
            //System.out.println("checking secret key");
            //System.out.println("current key: "+current_key.toHex());
            //System.out.println("key from proof: "+this.proof.secretKey.get().public_key().toHex());
            if (this.proof.secretKey.get().public_key().equals(current_key)) {
                //System.out.println("public keys are equal");

                return Right(null);
            } else {
                //System.out.println("public keys are not equal");

                return Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied"));
            }
        } else {
            //System.out.println("checking final signature");

            byte[] finalSignature = this.proof.signature.get();

            SignedBlock b;
            if (this.blocks.isEmpty()) {
                b = this.authority;
            } else {
                b = this.blocks.get(this.blocks.size() - 1);
            }

            byte[] block = b.block;
            org.biscuitsec.biscuit.crypto.PublicKey next_key = b.key;
            byte[] signature = b.signature;

            byte[] payload = BlockSignatureBuffer.getBufferSealedSignature(next_key, block, signature);

            if (KeyPair.verify(current_key, payload, finalSignature)) {
                return Right(null);
            } else {
                return Left(new Error.FormatError.Signature.SealedSignature());
            }

        }
    }

    static Either<Error, org.biscuitsec.biscuit.crypto.PublicKey> verifyBlockSignature(SignedBlock signedBlock, org.biscuitsec.biscuit.crypto.PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] block = signedBlock.block;
        org.biscuitsec.biscuit.crypto.PublicKey next_key = signedBlock.key;
        byte[] signature = signedBlock.signature;

        var signatureLengthError = PublicKey.validateSignatureLength(publicKey.algorithm, signature.length);
        if (signatureLengthError.isPresent()) {
            return Left(signatureLengthError.get());
        }

        ByteBuffer algo_buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        algo_buf.putInt(Integer.valueOf(next_key.algorithm.getNumber()));
        algo_buf.flip();

        Signature sgr = KeyPair.generateSignature(publicKey.algorithm);
        sgr.initVerify(publicKey.key);
        sgr.update(block);
        if(signedBlock.externalSignature.isDefined()) {
            sgr.update(signedBlock.externalSignature.get().signature);
        }
        sgr.update(algo_buf);
        sgr.update(next_key.toBytes());
        byte[] payload = BlockSignatureBuffer.getBufferSignature(next_key, block, signedBlock.externalSignature.toJavaOptional());
        if (!KeyPair.verify(publicKey, payload, signature)) {
            return Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied"));
        }

        if (signedBlock.externalSignature.isDefined()) {
            byte[] externalPayload = BlockSignatureBuffer.getBufferSignature(publicKey, block);
            ExternalSignature externalSignature = signedBlock.externalSignature.get();

            if (!KeyPair.verify(externalSignature.key, externalPayload, externalSignature.signature)) {
                return Left(new Error.FormatError.Signature.InvalidSignature("external signature error: Verification equation was not satisfied"));
            }
        }

        return Right(next_key);
    }

    public Tuple2<Block, ArrayList<Block>> extractBlocks(SymbolTable symbols) throws Error {
        ArrayList<Option<org.biscuitsec.biscuit.crypto.PublicKey>> blockExternalKeys = new ArrayList<>();
        Either<Error.FormatError, Block> authRes = Block.from_bytes(this.authority.block, Option.none());
        if (authRes.isLeft()) {
            throw authRes.getLeft();
        }
        Block authority = authRes.get();
        for(org.biscuitsec.biscuit.crypto.PublicKey pk: authority.publicKeys()) {
            symbols.insert(pk);
        }
        blockExternalKeys.add(Option.none());

        for (String s : authority.symbols().symbols) {
            symbols.add(s);
        }

        ArrayList<Block> blocks = new ArrayList<>();
        for (SignedBlock bdata : this.blocks) {
            Option<org.biscuitsec.biscuit.crypto.PublicKey> externalKey = Option.none();
            if(bdata.externalSignature.isDefined()) {
                externalKey = Option.some(bdata.externalSignature.get().key);
            }
            Either<Error.FormatError, Block> blockRes = Block.from_bytes(bdata.block, externalKey);
            if (blockRes.isLeft()) {
                throw blockRes.getLeft();
            }
            Block block = blockRes.get();

            // blocks with external signatures keep their own symbol table
            if(bdata.externalSignature.isDefined()) {
                //symbols.insert(bdata.externalSignature.get().key);
                blockExternalKeys.add(Option.some(bdata.externalSignature.get().key));
            } else {
                blockExternalKeys.add(Option.none());
                for (String s : block.symbols().symbols) {
                    symbols.add(s);
                }
                for(org.biscuitsec.biscuit.crypto.PublicKey pk: block.publicKeys()) {
                    symbols.insert(pk);
                }
            }

            blocks.add(block);
        }

        return new Tuple2<>(authority, blocks);
    }

    public Either<Error, Void> seal() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        if (this.proof.secretKey.isEmpty()) {
            return Left(new Error.Sealed());
        }

        SignedBlock block;
        if (this.blocks.isEmpty()) {
            block = this.authority;
        } else {
            block = this.blocks.get(this.blocks.size() - 1);
        }

        KeyPair secretKey = this.proof.secretKey.get();
        byte[] payload = BlockSignatureBuffer.getBufferSealedSignature(block.key, block.block, block.signature);
        byte[] signature = secretKey.sign(payload);

        this.proof.secretKey = Option.none();
        this.proof.signature = Option.some(signature);

        return Right(null);
    }

    public List<byte[]> revocation_identifiers() {
        ArrayList<byte[]> l = new ArrayList<>();
        l.add(this.authority.signature);

        for (SignedBlock block : this.blocks) {
            l.add(block.signature);
        }
        return l;
    }

    SerializedBiscuit(SignedBlock authority, List<SignedBlock> blocks, Proof proof) {
        this.authority = authority;
        this.blocks = blocks;
        this.proof = proof;
        this.root_key_id = Option.none();
    }

    SerializedBiscuit(SignedBlock authority, List<SignedBlock> blocks, Proof proof, Option<Integer> root_key_id) {
        this.authority = authority;
        this.blocks = blocks;
        this.proof = proof;
        this.root_key_id = root_key_id;
    }
}
