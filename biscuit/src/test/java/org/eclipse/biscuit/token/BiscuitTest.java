/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.eclipse.biscuit.crypto.TokenSignature.hex;
import static org.eclipse.biscuit.token.builder.Utils.check;
import static org.eclipse.biscuit.token.builder.Utils.date;
import static org.eclipse.biscuit.token.builder.Utils.fact;
import static org.eclipse.biscuit.token.builder.Utils.pred;
import static org.eclipse.biscuit.token.builder.Utils.rule;
import static org.eclipse.biscuit.token.builder.Utils.str;
import static org.eclipse.biscuit.token.builder.Utils.var;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import biscuit.format.schema.Schema;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.eclipse.biscuit.crypto.KeyDelegate;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.FailedCheck;
import org.eclipse.biscuit.error.LogicError;
import org.eclipse.biscuit.token.builder.AuthorizerBuilder;
import org.eclipse.biscuit.token.builder.Block;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BiscuitTest {

  private SecureRandom rng;

  @BeforeEach
  public void setUp() throws NoSuchAlgorithmException {
    byte[] seed = {0, 0, 0, 0};
    rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(seed);
  }

  @Test
  public void testBasic()
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {

    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block authorityBuilder = new Block();

    authorityBuilder.addFact(fact("right", Arrays.asList(str("file1"), str("read"))));
    authorityBuilder.addFact(fact("right", Arrays.asList(str("file2"), str("read"))));
    authorityBuilder.addFact(fact("right", Arrays.asList(str("file1"), str("write"))));

    Biscuit b = Biscuit.make(rng, root, authorityBuilder.build());

    System.out.println(b.print());

    System.out.println("serializing the first token");

    byte[] data = b.serialize();

    System.out.print("data len: ");
    System.out.println(data.length);
    System.out.println(hex(data));

    System.out.println("deserializing the first token");
    Biscuit deser = Biscuit.fromBytes(data, root.getPublicKey());
    assertEquals(1, deser.blockCount());

    System.out.println(deser.print());

    // SECOND BLOCK
    System.out.println("preparing the second block");

    KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block builder = deser.createBlock();
    builder.addCheck(
        check(
            rule(
                "caveat1",
                List.of(var("resource")),
                Arrays.asList(
                    pred("resource", List.of(var("resource"))),
                    pred("operation", List.of(str("read"))),
                    pred("right", Arrays.asList(var("resource"), str("read")))))));

    Biscuit b2 = deser.attenuate(rng, keypair2, builder);

    System.out.println(b2.print());

    System.out.println("serializing the second token");

    byte[] data2 = b2.serialize();

    System.out.print("data len: ");
    System.out.println(data2.length);
    System.out.println(hex(data2));

    System.out.println("deserializing the second token");
    Biscuit deser2 = Biscuit.fromBytes(data2, root.getPublicKey());
    assertEquals(2, deser2.blockCount());

    System.out.println(deser2.print());

    // THIRD BLOCK
    System.out.println("preparing the third block");

    KeyPair keypair3 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block builder3 = deser2.createBlock();
    builder3.addCheck(
        check(
            rule(
                "caveat2",
                List.of(str("file1")),
                List.of(pred("resource", List.of(str("file1")))))));

    Biscuit b3 = deser2.attenuate(rng, keypair3, builder3);

    System.out.println(b3.print());

    System.out.println("serializing the third token");

    byte[] data3 = b3.serialize();

    System.out.print("data len: ");
    System.out.println(data3.length);
    System.out.println(hex(data3));

    System.out.println("deserializing the third token");
    Biscuit finalToken = Biscuit.fromBytes(data3, root.getPublicKey());
    assertEquals(3, finalToken.blockCount());

    System.out.println(finalToken.print());

    // check
    System.out.println("will check the token for resource=file1 and operation=read");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addFact("resource(\"file1\")");
    authorizerBuilder.addFact("operation(\"read\")");
    authorizerBuilder.addPolicy("allow if true");
    Authorizer authorizer = authorizerBuilder.build(finalToken);
    authorizer.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));

    System.out.println("will check the token for resource=file2 and operation=write");

    AuthorizerBuilder authorizer2Builder = new AuthorizerBuilder();
    authorizer2Builder.addFact("resource(\"file2\")");
    authorizer2Builder.addFact("operation(\"write\")");
    authorizer2Builder.addPolicy("allow if true");

    Authorizer authorizer2 = authorizer2Builder.build(finalToken);
    try {
      authorizer2.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));
    } catch (Error e) {
      System.out.println(e);
      assertEquals(
          new Error.FailedLogic(
              new LogicError.Unauthorized(
                  new LogicError.MatchedPolicy.Allow(0),
                  Arrays.asList(
                      new FailedCheck.FailedBlock(
                          1,
                          0,
                          "check if resource($resource), operation(\"read\"), right($resource,"
                              + " \"read\")"),
                      new FailedCheck.FailedBlock(2, 0, "check if resource(\"file1\")")))),
          e);
    }
  }

  @Test
  public void testFolders() throws NoSuchAlgorithmException, Error {
    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    org.eclipse.biscuit.token.builder.Biscuit builder = Biscuit.builder(rng, root);

    builder.addRight("/folder1/file1", "read");
    builder.addRight("/folder1/file1", "write");
    builder.addRight("/folder1/file2", "read");
    builder.addRight("/folder1/file2", "write");
    builder.addRight("/folder2/file3", "read");

    System.out.println(builder.build());
    Biscuit b = builder.build();

    System.out.println(b.print());

    Block block2 = b.createBlock();
    block2.resourcePrefix("/folder1/");
    block2.checkRight("read");

    KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    Biscuit b2 = b.attenuate(rng, keypair2, block2);

    AuthorizerBuilder v1Builder = new AuthorizerBuilder();
    v1Builder.addFact("resource(\"/folder1/file1\")");
    v1Builder.addFact("operation(\"read\")");
    v1Builder.allow();
    Authorizer v1 = v1Builder.build(b2);
    v1.authorize();

    AuthorizerBuilder v2Builder = new AuthorizerBuilder();
    v2Builder.addFact("resource(\"/folder2/file3\")");
    v2Builder.addFact("operation(\"read\")");
    v2Builder.allow();
    Authorizer v2 = v2Builder.build(b2);
    try {
      v2.authorize();
      fail();
    } catch (Error e2) {
      // Empty
    }

    AuthorizerBuilder v3Builder = new AuthorizerBuilder();
    v3Builder.addFact("resource(\"/folder2/file1\")");
    v3Builder.addFact("operation(\"write\")");
    v3Builder.allow();
    Authorizer v3 = v3Builder.build(b2);
    try {
      v3.authorize();
      fail();
    } catch (Error e) {
      System.out.println(v3.formatWorld());
      for (FailedCheck f : e.getFailedChecks().get()) {
        System.out.println(f.toString());
      }
      assertEquals(
          new Error.FailedLogic(
              new LogicError.Unauthorized(
                  new LogicError.MatchedPolicy.Allow(0),
                  Arrays.asList(
                      new FailedCheck.FailedBlock(
                          1,
                          0,
                          "check if resource($resource), $resource.starts_with(\"/folder1/\")"),
                      new FailedCheck.FailedBlock(
                          1,
                          1,
                          "check if resource($resource), operation(\"read\"), right($resource,"
                              + " \"read\")")))),
          e);
    }
  }

  @Test
  public void testMultipleAttenuation()
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    SecureRandom rng = new SecureRandom();
    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block authorityBuilder = new Block();
    Date date = Date.from(Instant.now());
    authorityBuilder.addFact(fact("revocation_id", List.of(date(date))));

    Biscuit biscuit = Biscuit.make(rng, root, authorityBuilder.build());

    Block builder = biscuit.createBlock();
    builder.addFact(
        fact(
            "right",
            Arrays.asList(
                str("topic"), str("tenant"), str("namespace"), str("topic"), str("produce"))));

    String attenuatedB64 =
        biscuit
            .attenuate(rng, KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng), builder)
            .serializeBase64Url();

    System.out.println("attenuated: " + attenuatedB64);

    Biscuit.fromBase64Url(attenuatedB64, root.getPublicKey());
    String attenuated2B64 =
        biscuit
            .attenuate(rng, KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng), builder)
            .serializeBase64Url();

    System.out.println("attenuated2: " + attenuated2B64);
    Biscuit.fromBase64Url(attenuated2B64, root.getPublicKey());
  }

  @Test
  public void testReset() throws Error, NoSuchAlgorithmException {
    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    org.eclipse.biscuit.token.builder.Biscuit builder = Biscuit.builder(rng, root);

    builder.addRight("/folder1/file1", "read");
    builder.addRight("/folder1/file1", "write");
    builder.addRight("/folder1/file2", "read");
    builder.addRight("/folder1/file2", "write");
    builder.addRight("/folder2/file3", "read");

    System.out.println(builder.build());
    Biscuit b = builder.build();

    System.out.println(b.print());

    Block block2 = b.createBlock();
    block2.resourcePrefix("/folder1/");
    block2.checkRight("read");

    KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    Biscuit b2 = b.attenuate(rng, keypair2, block2);

    AuthorizerBuilder v1Builder = new AuthorizerBuilder();
    v1Builder.allow();

    Authorizer v2 =
        new AuthorizerBuilder()
            .merge(v1Builder)
            .addFact("resource(\"/folder1/file1\")")
            .addFact("operation(\"read\")")
            .build(b2);

    v2.authorize();

    Authorizer v3 =
        new AuthorizerBuilder()
            .merge(v1Builder)
            .addFact("resource(\"/folder2/file3\")")
            .addFact("operation(\"read\")")
            .build(b2);

    Assertions.assertThrows(Error.class, v3::authorize);
    System.out.println(v3.formatWorld());

    Authorizer v4 =
        new AuthorizerBuilder()
            .merge(v1Builder)
            .addFact("resource(\"/folder2/file1\")")
            .addFact("operation(\"write\")")
            .build(b2);

    var e = Assertions.assertThrows(Error.class, v4::authorize);

    System.out.println(v4.formatWorld());
    for (FailedCheck f : e.getFailedChecks().get()) {
      System.out.println(f.toString());
    }
    assertEquals(
        new Error.FailedLogic(
            new LogicError.Unauthorized(
                new LogicError.MatchedPolicy.Allow(0),
                Arrays.asList(
                    new FailedCheck.FailedBlock(
                        1, 0, "check if resource($resource), $resource.starts_with(\"/folder1/\")"),
                    new FailedCheck.FailedBlock(
                        1,
                        1,
                        "check if resource($resource), operation(\"read\"), right($resource,"
                            + " \"read\")")))),
        e);
  }

  @Test
  public void testEmptyAuthorizer() throws Error, NoSuchAlgorithmException {
    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    org.eclipse.biscuit.token.builder.Biscuit builder = Biscuit.builder(rng, root);

    builder.addRight("/folder1/file1", "read");
    builder.addRight("/folder1/file1", "write");
    builder.addRight("/folder1/file2", "read");
    builder.addRight("/folder1/file2", "write");
    builder.addRight("/folder2/file3", "read");

    System.out.println(builder.build());
    Biscuit b = builder.build();

    System.out.println(b.print());

    Block block2 = b.createBlock();
    block2.resourcePrefix("/folder1/");
    block2.checkRight("read");

    KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
    Biscuit b2 = b.attenuate(rng, keypair2, block2);

    AuthorizerBuilder v1Builder = new AuthorizerBuilder();
    v1Builder.allow();

    v1Builder.buildUnauthenticated().authorize();

    v1Builder.addFact("resource(\"/folder2/file1\")");
    v1Builder.addFact("operation(\"write\")");

    assertThrows(Error.class, v1Builder.build(b2)::authorize);
  }

  @Test
  public void testBasicWithNamespaces()
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block authorityBuilder = new Block();

    authorityBuilder.addFact(fact("namespace:right", Arrays.asList(str("file1"), str("read"))));
    authorityBuilder.addFact(fact("namespace:right", Arrays.asList(str("file1"), str("write"))));
    authorityBuilder.addFact(fact("namespace:right", Arrays.asList(str("file2"), str("read"))));
    Biscuit b = Biscuit.make(rng, root, authorityBuilder.build());

    System.out.println(b.print());

    System.out.println("serializing the first token");

    byte[] data = b.serialize();

    System.out.print("data len: ");
    System.out.println(data.length);
    System.out.println(hex(data));

    System.out.println("deserializing the first token");
    Biscuit deser = Biscuit.fromBytes(data, root.getPublicKey());

    System.out.println(deser.print());

    // SECOND BLOCK
    System.out.println("preparing the second block");

    KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block builder = deser.createBlock();
    builder.addCheck(
        check(
            rule(
                "caveat1",
                List.of(var("resource")),
                Arrays.asList(
                    pred("resource", List.of(var("resource"))),
                    pred("operation", List.of(str("read"))),
                    pred("namespace:right", Arrays.asList(var("resource"), str("read")))))));

    Biscuit b2 = deser.attenuate(rng, keypair2, builder);

    System.out.println(b2.print());

    System.out.println("serializing the second token");

    byte[] data2 = b2.serialize();

    System.out.print("data len: ");
    System.out.println(data2.length);
    System.out.println(hex(data2));

    System.out.println("deserializing the second token");
    Biscuit deser2 = Biscuit.fromBytes(data2, root.getPublicKey());

    System.out.println(deser2.print());

    // THIRD BLOCK
    System.out.println("preparing the third block");

    KeyPair keypair3 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block builder3 = deser2.createBlock();
    builder3.addCheck(
        check(
            rule(
                "caveat2",
                List.of(str("file1")),
                List.of(pred("resource", List.of(str("file1")))))));

    Biscuit b3 = deser2.attenuate(rng, keypair3, builder3);

    System.out.println(b3.print());

    System.out.println("serializing the third token");

    byte[] data3 = b3.serialize();

    System.out.print("data len: ");
    System.out.println(data3.length);
    System.out.println(hex(data3));

    System.out.println("deserializing the third token");
    Biscuit finalToken = Biscuit.fromBytes(data3, root.getPublicKey());

    System.out.println(finalToken.print());

    // check
    System.out.println("will check the token for resource=file1 and operation=read");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addFact("resource(\"file1\")");
    authorizerBuilder.addFact("operation(\"read\")");
    authorizerBuilder.addPolicy("allow if true");
    Authorizer authorizer = authorizerBuilder.build(finalToken);
    authorizer.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));

    System.out.println("will check the token for resource=file2 and operation=write");

    AuthorizerBuilder authorizer2Builder = new AuthorizerBuilder();
    authorizer2Builder.addFact("resource(\"file2\")");
    authorizer2Builder.addFact("operation(\"write\")");
    authorizer2Builder.addPolicy("allow if true");

    Authorizer authorizer2 = authorizer2Builder.build(finalToken);
    try {
      authorizer2.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));
    } catch (Error e) {
      System.out.println(e);
      assertEquals(
          new Error.FailedLogic(
              new LogicError.Unauthorized(
                  new LogicError.MatchedPolicy.Allow(0),
                  Arrays.asList(
                      new FailedCheck.FailedBlock(
                          1,
                          0,
                          "check if resource($resource), operation(\"read\"),"
                              + " namespace:right($resource, \"read\")"),
                      new FailedCheck.FailedBlock(2, 0, "check if resource(\"file1\")")))),
          e);
    }
  }

  @Test
  public void testBasicWithNamespacesWithAddAuthorityFact()
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    org.eclipse.biscuit.token.builder.Biscuit o =
        new org.eclipse.biscuit.token.builder.Biscuit(rng, root);
    o.addAuthorityFact("namespace:right(\"file1\",\"read\")");
    o.addAuthorityFact("namespace:right(\"file1\",\"write\")");
    o.addAuthorityFact("namespace:right(\"file2\",\"read\")");
    Biscuit b = o.build();

    System.out.println(b.print());

    System.out.println("serializing the first token");

    byte[] data = b.serialize();

    System.out.print("data len: ");
    System.out.println(data.length);
    System.out.println(hex(data));

    System.out.println("deserializing the first token");
    Biscuit deser = Biscuit.fromBytes(data, root.getPublicKey());

    System.out.println(deser.print());

    // SECOND BLOCK
    System.out.println("preparing the second block");

    KeyPair keypair2 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block builder = deser.createBlock();
    builder.addCheck(
        check(
            rule(
                "caveat1",
                List.of(var("resource")),
                Arrays.asList(
                    pred("resource", List.of(var("resource"))),
                    pred("operation", List.of(str("read"))),
                    pred("namespace:right", Arrays.asList(var("resource"), str("read")))))));

    Biscuit b2 = deser.attenuate(rng, keypair2, builder);

    System.out.println(b2.print());

    System.out.println("serializing the second token");

    byte[] data2 = b2.serialize();

    System.out.print("data len: ");
    System.out.println(data2.length);
    System.out.println(hex(data2));

    System.out.println("deserializing the second token");
    Biscuit deser2 = Biscuit.fromBytes(data2, root.getPublicKey());

    System.out.println(deser2.print());

    // THIRD BLOCK
    System.out.println("preparing the third block");

    KeyPair keypair3 = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block builder3 = deser2.createBlock();
    builder3.addCheck(
        check(
            rule(
                "caveat2",
                List.of(str("file1")),
                List.of(pred("resource", List.of(str("file1")))))));

    Biscuit b3 = deser2.attenuate(rng, keypair3, builder3);

    System.out.println(b3.print());

    System.out.println("serializing the third token");

    byte[] data3 = b3.serialize();

    System.out.print("data len: ");
    System.out.println(data3.length);
    System.out.println(hex(data3));

    System.out.println("deserializing the third token");
    Biscuit finalToken = Biscuit.fromBytes(data3, root.getPublicKey());

    System.out.println(finalToken.print());

    // check
    System.out.println("will check the token for resource=file1 and operation=read");

    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addFact("resource(\"file1\")");
    authorizerBuilder.addFact("operation(\"read\")");
    authorizerBuilder.addPolicy("allow if true");
    Authorizer authorizer = authorizerBuilder.build(finalToken);
    authorizer.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));

    System.out.println("will check the token for resource=file2 and operation=write");

    AuthorizerBuilder authorizer2Builder = new AuthorizerBuilder();
    authorizer2Builder.addFact("resource(\"file2\")");
    authorizer2Builder.addFact("operation(\"write\")");
    authorizer2Builder.addPolicy("allow if true");
    Authorizer authorizer2 = authorizer2Builder.build(finalToken);
    try {
      authorizer2.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));
    } catch (Error e) {
      System.out.println(e);
      assertEquals(
          new Error.FailedLogic(
              new LogicError.Unauthorized(
                  new LogicError.MatchedPolicy.Allow(0),
                  Arrays.asList(
                      new FailedCheck.FailedBlock(
                          1,
                          0,
                          "check if resource($resource), operation(\"read\"),"
                              + " namespace:right($resource, \"read\")"),
                      new FailedCheck.FailedBlock(2, 0, "check if resource(\"file1\")")))),
          e);
    }
  }

  @Test
  public void testRootKeyId()
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Block authorityBuilder = new Block();

    authorityBuilder.addFact(fact("right", Arrays.asList(str("file1"), str("read"))));
    authorityBuilder.addFact(fact("right", Arrays.asList(str("file2"), str("read"))));
    authorityBuilder.addFact(fact("right", Arrays.asList(str("file1"), str("write"))));

    Biscuit b = Biscuit.make(rng, root, 1, authorityBuilder.build());

    System.out.println(b.print());

    System.out.println("serializing the first token");

    byte[] data = b.serialize();

    System.out.print("data len: ");
    System.out.println(data.length);
    System.out.println(hex(data));

    System.out.println("deserializing the first token");

    assertThrows(
        InvalidKeyException.class,
        () -> {
          Biscuit deser =
              Biscuit.fromBytes(
                  data,
                  new KeyDelegate() {
                    @Override
                    public Optional<PublicKey> getRootKey(Optional<Integer> keyId) {
                      return Optional.empty();
                    }
                  });
        });

    assertThrows(
        Error.FormatError.Signature.InvalidSignature.class,
        () -> {
          Biscuit deser =
              Biscuit.fromBytes(
                  data,
                  new KeyDelegate() {
                    @Override
                    public Optional<PublicKey> getRootKey(Optional<Integer> keyId) {
                      KeyPair root = null;
                      try {
                        root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
                      } catch (Error.FormatError e) {
                        throw new IllegalStateException(e);
                      }
                      return Optional.of(root.getPublicKey());
                    }
                  });
        });

    Biscuit deser =
        Biscuit.fromBytes(
            data,
            new KeyDelegate() {
              @Override
              public Optional<PublicKey> getRootKey(Optional<Integer> keyId) {
                if (keyId.get() == 1) {
                  return Optional.of(root.getPublicKey());
                } else {
                  return Optional.empty();
                }
              }
            });
  }

  @Test
  public void testCheckAll()
      throws Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    System.out.println("preparing the authority block");

    KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);

    Biscuit biscuit =
        Biscuit.builder(root)
            .addAuthorityCheck(
                "check all operation($op), allowed_operations($allowed), $allowed.contains($op)")
            .build();
    AuthorizerBuilder authorizerBuilder = new AuthorizerBuilder();
    authorizerBuilder.addFact("operation(\"read\")");
    authorizerBuilder.addFact("operation(\"write\")");
    authorizerBuilder.addFact("allowed_operations({\"write\"})");
    authorizerBuilder.addPolicy("allow if true");

    Authorizer authorizer = authorizerBuilder.build(biscuit.verify(root.getPublicKey()));
    try {
      authorizer.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));
    } catch (Error.FailedLogic e) {
      System.out.println(e);
      assertEquals(
          new Error.FailedLogic(
              new LogicError.Unauthorized(
                  new LogicError.MatchedPolicy.Allow(0),
                  List.of(
                      new FailedCheck.FailedBlock(
                          0,
                          0,
                          "check all operation($op), allowed_operations($allowed),"
                              + " $allowed.contains($op)")))),
          e);
    }

    AuthorizerBuilder authorizer2Builder = new AuthorizerBuilder();
    authorizer2Builder.addFact("operation(\"read\")");
    authorizer2Builder.addFact("operation(\"write\")");
    authorizer2Builder.addFact("allowed_operations({\"read\", \"write\"})");
    authorizer2Builder.addPolicy("allow if true");

    Authorizer authorizer2 = authorizer2Builder.build(biscuit.verify(root.getPublicKey()));
    authorizer2.authorize(new RunLimits(500, 100, Duration.ofMillis(500)));
  }
}
