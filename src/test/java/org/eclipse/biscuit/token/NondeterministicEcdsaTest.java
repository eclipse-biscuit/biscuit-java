/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.eclipse.biscuit.token.builder.Utils.fact;
import static org.eclipse.biscuit.token.builder.Utils.str;

import biscuit.format.schema.Schema;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.List;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Block;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/** Top-level test to ensure ECDSA with nondeterministic nonce also works. */
@Isolated
public class NondeterministicEcdsaTest {
  @BeforeAll
  static void beforeAll() {
    KeyPair.setSECP256R1Factory(KeyPair.DEFAULT_NONDETERMINISTIC_SECP256R1_FACTORY);
  }

  @AfterAll
  static void afterAll() {
    KeyPair.setSECP256R1Factory(KeyPair.DEFAULT_SECP256R1_FACTORY);
  }

  @Test
  public void simpleSigningTest()
      throws Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    var root = KeyPair.generate(Schema.PublicKey.Algorithm.SECP256R1);
    var b =
        Biscuit.make(
            new SecureRandom(),
            root,
            new Block().addFact(fact("foo", List.of(str("bar")))).build());
    Biscuit.fromBytes(b.serialize(), root.getPublicKey());
  }
}
