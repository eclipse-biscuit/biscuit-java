/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import biscuit.format.schema.Schema;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Block;

/* example code for the documentation at https://www.biscuitsec.org
 * if these functions change, please send a PR to update them at https://github.com/biscuit-auth/website
 */
public class ExampleTest {
  public KeyPair root() throws Error.FormatError {
    return KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519);
  }

  public Biscuit createToken(KeyPair root) throws Error {
    return Biscuit.builder(root)
        .addAuthorityFact("user(\"1234\")")
        .addAuthorityCheck("check if operation(\"read\")")
        .build();
  }

  public Long authorize(KeyPair root, byte[] serializedToken)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    return Biscuit.fromBytes(serializedToken, root.getPublicKey())
        .authorizer()
        .addFact("resource(\"/folder1/file1\")")
        .addFact("operation(\"read\")")
        .allow()
        .authorize();
  }

  public Biscuit attenuate(KeyPair root, byte[] serializedToken)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, Error {
    Biscuit token = Biscuit.fromBytes(serializedToken, root.getPublicKey());
    Block block = token.createBlock().addCheck("check if operation(\"read\")");
    return token.attenuate(block, root.getPublicKey().getAlgorithm());
  }
}
