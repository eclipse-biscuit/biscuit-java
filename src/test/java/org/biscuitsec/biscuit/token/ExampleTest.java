package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.builder.Block;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/* example code for the documentation at https://www.biscuitsec.org
 * if these functions change, please send a PR to update them at https://github.com/biscuit-auth/website
 */
public class ExampleTest {
    public KeyPair root() {
        return KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519);
    }

    public Biscuit createToken(KeyPair root) throws Error {
        return Biscuit.builder(root)
                .addAuthorityFact("user(\"1234\")")
                .addAuthorityCheck("check if operation(\"read\")")
                .build();
    }

    public Long authorize(KeyPair root, byte[] serializedToken) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        return Biscuit.fromBytes(serializedToken, root.getPublicKey()).authorizer()
                .addFact("resource(\"/folder1/file1\")")
                .addFact("operation(\"read\")")
                .allow()
                .authorize();
    }

    public Biscuit attenuate(KeyPair root, byte[] serializedToken) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
        Biscuit token = Biscuit.fromBytes(serializedToken, root.getPublicKey());
        Block block = token.createBlock().addCheck("check if operation(\"read\")");
        return token.attenuate(block, root.getPublicKey().algorithm);
    }

    /*public Set<Fact> query(Authorizer authorizer) throws Error.Timeout, Error.TooManyFacts, Error.TooManyIterations, Error.Parser {
        return authorizer.query("data($name, $id) <- user($name, $id)");
    }*/
}
