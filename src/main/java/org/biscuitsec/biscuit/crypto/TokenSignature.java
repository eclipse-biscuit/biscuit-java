package org.biscuitsec.biscuit.crypto;

import org.biscuitsec.biscuit.token.builder.Utils;

/**
 * Signature aggregation
 */
public final class TokenSignature {
    private TokenSignature() {}

    /*
    final ArrayList<RistrettoElement> parameters;
    final Scalar z;


    public TokenSignature(final SecureRandom rng, KeyPair keypair, byte[] message) {
        byte[] b = new byte[64];
        rng.nextBytes(b);
        Scalar r = Scalar.fromBytesModOrderWide(b);

        RistrettoElement A = Constants.RISTRETTO_GENERATOR.multiply(r);
        ArrayList<RistrettoElement> l = new ArrayList<>();
        l.add(A);
        Scalar d = hash_points(l);
        Scalar e = hash_message(keypair.public_key, message);

        Scalar z = r.multiply(d).subtract(e.multiply(keypair.private_key));

        this.parameters = l;
        this.z = z;
    }

    TokenSignature(final ArrayList<RistrettoElement> parameters, final Scalar z) {
        this.parameters = parameters;
        this.z = z;
    }


    public TokenSignature sign(final SecureRandom rng, KeyPair keypair, byte[] message) {
        byte[] b = new byte[64];
        rng.nextBytes(b);
        Scalar r = Scalar.fromBytesModOrderWide(b);

        RistrettoElement A = Constants.RISTRETTO_GENERATOR.multiply(r);
        ArrayList<RistrettoElement> l = new ArrayList<>();
        l.add(A);
        Scalar d = hash_points(l);
        Scalar e = hash_message(keypair.public_key, message);

        Scalar z = r.multiply(d).subtract(e.multiply(keypair.private_key));

        TokenSignature sig = new TokenSignature(this.parameters, this.z.add(z));
        sig.parameters.add(A);

        return sig;
    }


    public Either<Error, Void> verify(List<RistrettoElement> public_keys, List<byte[]> messages) {
        if (!(public_keys.size() == messages.size() && public_keys.size() == this.parameters.size())) {
            System.out.println(("lists are not the same size"));
            return Left(new Error.FormatError.Signature.InvalidFormat());
        }

        //System.out.println("z, zp");
        RistrettoElement zP = Constants.RISTRETTO_GENERATOR.multiply(this.z);
        //System.out.println(hex(z.toByteArray()));
        //System.out.println(hex(zP.compress().toByteArray()));


        //System.out.println("eiXi");
        RistrettoElement eiXi = RistrettoElement.IDENTITY;
        for(int i = 0; i < public_keys.size(); i++) {
            Scalar e = hash_message(public_keys.get(i), messages.get(i));
            //System.out.println(hex(e.toByteArray()));
            //System.out.println(hex((public_keys.get(i).multiply(e)).compress().toByteArray()));


            eiXi = eiXi.add(public_keys.get(i).multiply(e));
            //System.out.println(hex(eiXi.compress().toByteArray()));

        }

        //System.out.println("diAi");
        RistrettoElement diAi = RistrettoElement.IDENTITY;
        for (RistrettoElement A: parameters) {
            ArrayList<RistrettoElement> l = new ArrayList<>();
            l.add(A);
            Scalar d = hash_points(l);

            diAi = diAi.add(A.multiply(d));
        }

        //System.out.println(hex(eiXi.compress().toByteArray()));
        //System.out.println(hex(diAi.compress().toByteArray()));



        RistrettoElement res = zP.add(eiXi).subtract(diAi);

        //System.out.println(hex(RistrettoElement.IDENTITY.compress().toByteArray()));
        //System.out.println(hex(res.compress().toByteArray()));

        if (res.ctEquals(RistrettoElement.IDENTITY) == 1) {
            return Right(null);
        } else {
            return Left(new Error.FormatError.Signature.InvalidSignature("signature error: Verification equation was not satisfied"));
        }
    }

    public Schema.Signature serialize() {
        Schema.Signature.Builder sig = Schema.Signature.newBuilder()
                .setZ(ByteString.copyFrom(this.z.toByteArray()));

        //System.out.println(this.parameters.size());
        for (int i = 0; i < this.parameters.size(); i++) {
            //System.out.println(i);
            sig.addParameters(ByteString.copyFrom(this.parameters.get(i).compress().toByteArray()));
        }

        return sig.build();
    }


    static public  Either<Error, TokenSignature> deserialize(Schema.Signature sig) {
        try {
            ArrayList<RistrettoElement> parameters = new ArrayList<>();
            for (ByteString parameter : sig.getParametersList()) {
                parameters.add((new CompressedRistretto(parameter.toByteArray())).decompress());
            }

            //System.out.println(hex(sig.getZ().toByteArray()));
            //System.out.println(sig.getZ().toByteArray().length);

            Scalar z = Scalar.fromBytesModOrder(sig.getZ().toByteArray());

            return Right(new TokenSignature(parameters, z));
        } catch (InvalidEncodingException e) {
            return Left(new Error.FormatError.Signature.InvalidFormat());
        } catch(IllegalArgumentException e) {
            return Left(new Error.FormatError.DeserializationError(e.toString()));
        }
    }

    static Scalar hash_points(List<RistrettoElement> points) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.reset();

            for (RistrettoElement point : points) {
                digest.update(point.compress().toByteArray());
            }

            return Scalar.fromBytesModOrderWide(digest.digest());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static Scalar hash_message(RistrettoElement point, byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.reset();

            digest.update(point.compress().toByteArray());
            digest.update(data);

            return Scalar.fromBytesModOrderWide(digest.digest());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }*/

    static public String hex(byte[] byteArray) {
        StringBuilder result = new StringBuilder();
        for (byte bb : byteArray) {
            result.append(String.format("%02X", bb));
        }
        return result.toString();
    }

    public static byte[] fromHex(String s) {
        return Utils.hexStringToByteArray(s);
    }
}
