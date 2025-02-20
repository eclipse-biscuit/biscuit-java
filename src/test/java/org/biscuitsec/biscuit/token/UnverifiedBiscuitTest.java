package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.RunLimits;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.error.FailedCheck;
import org.biscuitsec.biscuit.error.LogicError;
import org.biscuitsec.biscuit.token.builder.Block;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UnverifiedBiscuitTest {

    @Test
    public void testBasic() throws Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);

        System.out.println("preparing the authority block, block0");

        KeyPair keypair0 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

       // org.biscuitsec.biscuit.token.builder.Block block0 = new org.biscuitsec.biscuit.token.builder.Block(0);
       org.biscuitsec.biscuit.token.builder.Biscuit block0 = Biscuit.builder(rng, keypair0);
        block0.addAuthorityFact(Utils.fact("right", List.of(Utils.s("file1"), Utils.s("read"))));
        block0.addAuthorityFact(Utils.fact("right", List.of(Utils.s("file2"), Utils.s("read"))));
        block0.addAuthorityFact(Utils.fact("right", List.of(Utils.s("file1"), Utils.s("write"))));


        Biscuit biscuit0 = block0.build();

        System.out.println(biscuit0.print());
        System.out.println("serializing the first token");

        String data = biscuit0.serializeBase64Url();

        System.out.print("data len: ");
        System.out.println(data.length());
        System.out.println(data);

        System.out.println("deserializing the first token");
        UnverifiedBiscuit deser0 = UnverifiedBiscuit.fromBase64Url(data);
        System.out.println(deser0.print());

        // SECOND BLOCK
        System.out.println("preparing the second block");

        KeyPair keypair1 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
        org.biscuitsec.biscuit.token.builder.Block block1 = deser0.createBlock();
        block1.addCheck(Utils.check(Utils.rule(
                "caveat1",
                List.of(Utils.var("resource")),
                List.of(
                        Utils.pred("resource", List.of(Utils.var("resource"))),
                        Utils.pred("operation", List.of(Utils.s("read"))),
                        Utils.pred("right", List.of(Utils.var("resource"), Utils.s("read")))
                )
        )));
        UnverifiedBiscuit unverifiedBiscuit1 = deser0.attenuate(rng, keypair1, block1.build());

        System.out.println(unverifiedBiscuit1.print());

        System.out.println("serializing the second token");

        String data1 = unverifiedBiscuit1.serializeBase64Url();

        System.out.print("data len: ");
        System.out.println(data1.length());
        System.out.println(data1);

        System.out.println("deserializing the second token");
        UnverifiedBiscuit deser1 = UnverifiedBiscuit.fromBase64Url(data1);

        System.out.println(deser1.print());

        // THIRD BLOCK
        System.out.println("preparing the third block");

        KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

        Block block2 = unverifiedBiscuit1.createBlock();
        block2.addCheck(Utils.check(Utils.rule(
                "caveat2",
                List.of(Utils.s("file1")),
                List.of(
                        Utils.pred("resource", List.of(Utils.s("file1")))
                )
        )));

        UnverifiedBiscuit unverifiedBiscuit2 = unverifiedBiscuit1.attenuate(rng, keypair2, block2);

        System.out.println(unverifiedBiscuit2.print());

        System.out.println("serializing the third token");

        String data2 = unverifiedBiscuit2.serializeBase64Url();

        System.out.print("data len: ");
        System.out.println(data2.length());
        System.out.println(data2);

        System.out.println("deserializing the third token");
        UnverifiedBiscuit finalUnverifiedBiscuit = UnverifiedBiscuit.fromBase64Url(data2);

        System.out.println(finalUnverifiedBiscuit.print());

        // Crate Biscuit from UnverifiedBiscuit
        Biscuit finalBiscuit = finalUnverifiedBiscuit.verify(keypair0.getPublicKey());

        // check
        System.out.println("will check the token for resource=file1 and operation=read");

        Authorizer authorizer = finalBiscuit.authorizer();
        authorizer.addFact("resource(\"file1\")");
        authorizer.addFact("operation(\"read\")");
        authorizer.addPolicy("allow if true");
        authorizer.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));

        System.out.println("will check the token for resource=file2 and operation=write");

        Authorizer authorizer2 = finalBiscuit.authorizer();
        authorizer2.addFact("resource(\"file2\")");
        authorizer2.addFact("operation(\"write\")");
        authorizer2.addPolicy("allow if true");

        try {
            authorizer2.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));
        } catch (Error e) {
            System.out.println(e);
            assertEquals(
                    new Error.FailedLogic(new LogicError.Unauthorized(new LogicError.MatchedPolicy.Allow(0), Arrays.asList(
                            new FailedCheck.FailedBlock(1, 0, "check if resource($resource), operation(\"read\"), right($resource, \"read\")"),
                            new FailedCheck.FailedBlock(2, 0, "check if resource(\"file1\")")
                    ))),
                    e);
        }
    }
}