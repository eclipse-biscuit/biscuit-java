/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.eclipse.biscuit.crypto.TokenSignature.hex;
import static org.eclipse.biscuit.token.builder.Utils.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import biscuit.format.schema.Schema;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Error.Parser;
import org.eclipse.biscuit.error.FailedCheck;
import org.eclipse.biscuit.error.LogicError;
import org.eclipse.biscuit.token.builder.Block;
import org.eclipse.biscuit.token.builder.Term;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AuthorizerTest {
  final RunLimits runLimits = new RunLimits(500, 100, Duration.ofMillis(500));
  private SecureRandom rng;

  @BeforeEach
  public void setUp() throws Exception {
    byte[] seed = {0, 0, 0, 0};
    rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(seed);
  }

  @Test
  public void testAuthorizerPolicy() throws Parser {
    Authorizer authorizer = new Authorizer();
    List<Policy> policies = authorizer.getPolicies();
    authorizer.deny();
    assertEquals(1, policies.size());

    authorizer.addPolicy(
        new Policy(
            Arrays.asList(
                constrainedRule(
                    "deny",
                    new ArrayList<>(),
                    new ArrayList<>(),
                    Arrays.asList(new Term.Bool(true)))),
            Policy.Kind.DENY));
    assertEquals(2, policies.size());

    authorizer.addPolicy("deny if true");
    assertEquals(3, policies.size());
  }

  @Test
  public void ruleSetHashIssue() throws Exception {
    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    org.eclipse.biscuit.token.builder.Block authorityBuilder = new org.eclipse.biscuit.token.builder.Block();

    authorityBuilder.addFact(fact("right", Arrays.asList(str("file1"), str("read"))));
    authorityBuilder.addFact(fact("right", Arrays.asList(str("file2"), str("read"))));
    authorityBuilder.addFact(fact("right", Arrays.asList(str("file1"), str("write"))));

    Biscuit b = Biscuit.make(rng, root, authorityBuilder.build());

    byte[] data = b.serialize();

    Biscuit deser = Biscuit.fromBytes(data, root.getPublicKey());
    assertEquals(1, deser.blockCount());

    KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    org.eclipse.biscuit.token.builder.Block builder = deser.createBlock();
    builder.addCheck(
            check(
                    rule(
                            "caveat1",
                            List.of(var("resource")),
                            Arrays.asList(
                                    pred("resource", List.of(var("resource"))),
                                    pred("operation", List.of(str("read"))),
                                    pred("right", Arrays.asList(var("resource"), str("read")))))));

    builder.addRule("left($0, $1) <- right($0, $1)");
    builder.addRule("straight($0, $1) <- right($0, $1)");

    Biscuit b2 = deser.attenuate(rng, keypair2, builder);

    byte[] data2 = b2.serialize();

    Biscuit finalToken = Biscuit.fromBytes(data2, root.getPublicKey());
    assertEquals(2, finalToken.blockCount());

    Authorizer authorizer = finalToken.authorizer();
    authorizer.addFact("resource(\"file1\")");
    authorizer.addFact("operation(\"read\")");
    authorizer.addPolicy("allow if true");
    authorizer.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));

//    Authorizer authorizer2 = finalToken.authorizer();
//    authorizer2.addFact("resource(\"file2\")");
//    authorizer2.addFact("operation(\"write\")");
//    authorizer2.addPolicy("allow if true");

//    try {
//      authorizer2.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));
//    } catch (Error e) {
//      System.out.println(e);
//      assertEquals(
//              new Error.FailedLogic(
//                      new LogicError.Unauthorized(
//                              new LogicError.MatchedPolicy.Allow(0),
//                              Arrays.asList(
//                                      new FailedCheck.FailedBlock(
//                                              1,
//                                              0,
//                                              "check if resource($resource), operation(\"read\"), right($resource,"
//                                                      + " \"read\")"),
//                                      new FailedCheck.FailedBlock(2, 0, "check if resource(\"file1\")")))),
//              e);
//    }


  }

  @Test
  public void testPuttingSomeFactsInBiscuitAndGettingThemBackOutAgain() throws Exception {
    KeyPair keypair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Biscuit token =
        Biscuit.builder(keypair)
            .addAuthorityFact("email(\"bob@example.com\")")
            .addAuthorityFact("id(123)")
            .addAuthorityFact("enabled(true)")
            .addAuthorityFact("perms({1,2,3})")
            .build();

    Authorizer authorizer =
        Biscuit.fromBase64Url(token.serializeBase64Url(), keypair.getPublicKey())
            .verify(keypair.getPublicKey())
            .authorizer();

    Term emailTerm = queryFirstResult(authorizer, "emailfact($name) <- email($name)");
    assertEquals("bob@example.com", ((Term.Str) emailTerm).getValue());

    Term idTerm = queryFirstResult(authorizer, "idfact($name) <- id($name)");
    assertEquals(123, ((Term.Integer) idTerm).getValue());

    Term enabledTerm = queryFirstResult(authorizer, "enabledfact($name) <- enabled($name)");
    assertEquals(true, ((Term.Bool) enabledTerm).getValue());

    Term permsTerm = queryFirstResult(authorizer, "permsfact($name) <- perms($name)");
    assertEquals(
        Set.of(new Term.Integer(1), new Term.Integer(2), new Term.Integer(3)),
        ((Term.Set) permsTerm).getValue());
  }

  @Test
  public void testDatalogAuthorizer() throws Exception {
    KeyPair keypair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Biscuit token =
        Biscuit.builder(keypair)
            .addAuthorityFact("email(\"bob@example.com\")")
            .addAuthorityFact("id(123)")
            .addAuthorityFact("enabled(true)")
            .addAuthorityFact("perms({1,2,3})")
            .build();

    Authorizer authorizer =
        Biscuit.fromBase64Url(token.serializeBase64Url(), keypair.getPublicKey())
            .verify(keypair.getPublicKey())
            .authorizer();

    String l0 = "right($email) <- email($email)";
    String l1 = "check if right(\"bob@example.com\")";
    String l2 = "allow if true";
    String datalog = String.join(";", Arrays.asList(l0, l1, l2));
    authorizer.addDatalog(datalog);

    assertDoesNotThrow(() -> authorizer.authorize(runLimits));

    Term emailTerm = queryFirstResult(authorizer, "right($address) <- email($address)");
    assertEquals("bob@example.com", ((Term.Str) emailTerm).getValue());
  }

  private static Term queryFirstResult(Authorizer authorizer, String query) throws Error {
    return authorizer.query(query).iterator().next().terms().get(0);
  }
}
