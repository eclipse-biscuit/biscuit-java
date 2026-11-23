/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.junit.jupiter.api.Assertions.*;

import biscuit.format.schema.Schema;
import biscuit.format.schema.Schema.PublicKey.Algorithm;
import com.google.protobuf.ByteString;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.eclipse.biscuit.crypto.KeyDelegate;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.datalog.Check;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Error.FormatError.DeserializationLimitError.Reason;
import org.eclipse.biscuit.token.DeserializationLimit.MapKeyType;
import org.eclipse.biscuit.token.DeserializationLimit.PerBlock;
import org.eclipse.biscuit.token.DeserializationLimit.TermType;
import org.eclipse.biscuit.token.DeserializationLimit.TrustedScopeKind;
import org.eclipse.biscuit.token.builder.Block;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DeserializationLimitsTest {
  /** Fills in a block with the features that a test wants the block to contain */
  private interface BlockSetup {
    void apply(Block block) throws Exception;
  }

  private SecureRandom rng;
  private KeyPair root;

  @BeforeEach
  public void setUp() throws Exception {
    byte[] seed = {0, 0, 0, 0};
    rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(seed);
    root = KeyPair.generate(Algorithm.Ed25519, rng);
  }

  // Every setting must be at its most restrictive value in allowNothing, including settings added
  // in the future, so this checks each field by reflection rather than by name
  @Test
  public void testAllowNothingAllowsNothing() throws Exception {
    assertAllowsNothing(DeserializationLimit.allowNothing(), "allowNothing");
  }

  @Test
  public void testPerBlockAllowNothingAllowsNothing() throws Exception {
    assertAllowsNothing(PerBlock.allowNothing(), "PerBlock.allowNothing");
  }

  private void assertAllowsNothing(Object value, String path) throws Exception {
    int checked = 0;
    for (Field field : value.getClass().getDeclaredFields()) {
      if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
        continue;
      }
      checked++;
      field.setAccessible(true);
      Object fieldValue = field.get(value);
      String fieldPath = path + "." + field.getName();
      if (field.getType() == boolean.class) {
        assertFalse((boolean) fieldValue, fieldPath + " should be false");
      } else if (field.getType() == int.class && field.getName().equals("minSignatureVersion")) {
        assertEquals(1, fieldValue, fieldPath + " should be the highest supported version");
      } else if (field.getType() == int.class) {
        assertEquals(0, fieldValue, fieldPath + " should be 0");
      } else if (Set.class.isAssignableFrom(field.getType())) {
        // null would allow anything
        assertNotNull(fieldValue, fieldPath + " should be an empty set, not null");
        assertTrue(((Set<?>) fieldValue).isEmpty(), fieldPath + " should be empty");
      } else if (field.getType() == PerBlock.class) {
        assertAllowsNothing(fieldValue, fieldPath);
      } else {
        throw new AssertionError(fieldPath + " has a type this test doesn't know how to check");
      }
    }
    assertTrue(checked > 0, path + " has no fields to check");
  }

  @Test
  public void testAllowNothingRejectsAToken() throws Exception {
    byte[] token = authority(b -> b.addFact("a(1)")).serialize();
    assertRejected(Reason.TOKEN_TOO_LARGE, token, DeserializationLimit.allowNothing());
  }

  // these are the messages that biscuit-swift's DeserializationLimitError uses
  @Test
  public void testErrorMessagesMatchBiscuitSwift() throws Exception {
    byte[] token = authority(b -> b.addFact("a(1)")).serialize();
    Error.FormatError.DeserializationLimitError tooLarge =
        assertThrows(
            Error.FormatError.DeserializationLimitError.class,
            () ->
                Biscuit.fromBytes(
                    token,
                    root.getPublicKey(),
                    DeserializationLimit.allowEverything().setMaxTokenSize(0)));
    assertEquals("Biscuit is too large", tooLarge.getMessage());
    assertEquals("Biscuit Datalog block is too large", Reason.BLOCK_TOO_LARGE.description());
    assertEquals("Biscuit block contains too many facts", Reason.TOO_MANY_FACTS.description());
    assertEquals(
        "Biscuit contains attenuations without external signatures, which are not allowed",
        Reason.ATTENUATIONS_WITHOUT_EXTERNAL_SIGNATURES_NOT_ALLOWED.description());
  }

  @Test
  public void testAllowEverythingAcceptsAToken() throws Exception {
    Biscuit token =
        authority(
                b -> {
                  b.addFact("a(1)");
                  b.addCheck("check if [1, 2].all($x -> $x > 0)");
                })
            .attenuate(new Block().addCheck("check if a(1)"), Algorithm.Ed25519);
    byte[] bytes = token.serialize();

    assertEquals(
        token.print(),
        Biscuit.fromBytes(bytes, root.getPublicKey(), DeserializationLimit.allowEverything())
            .print());
  }

  @Test
  public void testMaxTokenSize() throws Exception {
    byte[] token = authority(b -> b.addFact("a(1)")).serialize();
    assertAccepted(token, DeserializationLimit.allowEverything().setMaxTokenSize(token.length));
    assertRejected(
        Reason.TOKEN_TOO_LARGE,
        token,
        DeserializationLimit.allowEverything().setMaxTokenSize(token.length - 1));
  }

  @Test
  public void testMaxBlocks() throws Exception {
    byte[] token =
        authority(b -> b.addFact("a(1)"))
            .attenuate(new Block().addCheck("check if a(1)"), Algorithm.Ed25519)
            .serialize();
    assertAccepted(token, DeserializationLimit.allowEverything().setMaxBlocks(2));
    assertRejected(
        Reason.TOO_MANY_BLOCKS, token, DeserializationLimit.allowEverything().setMaxBlocks(1));
  }

  @Test
  public void testSealedAndUnsealedTokens() throws Exception {
    Biscuit unsealed = authority(b -> b.addFact("a(1)"));
    byte[] unsealedBytes = unsealed.serialize();
    Biscuit sealed = Biscuit.fromBytes(unsealedBytes, root.getPublicKey());
    assertTrue(sealed.serializedBiscuit.seal().isOk());
    byte[] sealedBytes = sealed.serialize();

    DeserializationLimit noSealed =
        DeserializationLimit.allowEverything().setAllowSealedTokens(false);
    DeserializationLimit noUnsealed =
        DeserializationLimit.allowEverything().setAllowUnsealedTokens(false);
    assertAccepted(unsealedBytes, noSealed);
    assertAccepted(sealedBytes, noUnsealed);
    assertRejected(Reason.SEALED_TOKENS_NOT_ALLOWED, sealedBytes, noSealed);
    assertRejected(Reason.UNSEALED_TOKENS_NOT_ALLOWED, unsealedBytes, noUnsealed);
  }

  @Test
  public void testAttenuationsWithAndWithoutExternalSignatures() throws Exception {
    KeyPair external = KeyPair.generate(Algorithm.Ed25519, rng);
    Biscuit plain = authority(b -> b.addFact("a(1)"));
    byte[] withoutExternal =
        plain.attenuate(new Block().addCheck("check if a(1)"), Algorithm.Ed25519).serialize();
    byte[] withExternal = thirdPartyToken(plain, external).serialize();

    DeserializationLimit noExternal =
        DeserializationLimit.allowEverything().setAllowAttenuationsWithExternalSignatures(false);
    DeserializationLimit onlyExternal =
        DeserializationLimit.allowEverything().setAllowAttenuationsWithoutExternalSignatures(false);

    assertAccepted(withoutExternal, noExternal);
    assertAccepted(withExternal, onlyExternal);
    assertRejected(
        Reason.ATTENUATIONS_WITH_EXTERNAL_SIGNATURES_NOT_ALLOWED, withExternal, noExternal);
    assertRejected(
        Reason.ATTENUATIONS_WITHOUT_EXTERNAL_SIGNATURES_NOT_ALLOWED, withoutExternal, onlyExternal);
    // the authority block is not an attenuation
    assertAccepted(plain.serialize(), onlyExternal);
  }

  @Test
  public void testInternalSigningAlgorithms() throws Exception {
    KeyPair secp = KeyPair.generate(Algorithm.SECP256R1, rng);
    byte[] ed25519Token = authority(b -> b.addFact("a(1)")).serialize();
    byte[] secpToken = authorityWith(secp, b -> b.addFact("a(1)")).serialize();

    DeserializationLimit onlyEd25519 =
        DeserializationLimit.allowEverything()
            .setAllowedInternalSigningAlgorithms(Set.of(Algorithm.Ed25519));
    DeserializationLimit onlySecp =
        DeserializationLimit.allowEverything()
            .setAllowedInternalSigningAlgorithms(Set.of(Algorithm.SECP256R1));

    assertAccepted(ed25519Token, root, onlyEd25519);
    assertAccepted(secpToken, secp, onlySecp);
    assertRejected(Reason.INTERNAL_SIGNING_ALGORITHM_NOT_ALLOWED, ed25519Token, root, onlySecp);
    assertRejected(Reason.INTERNAL_SIGNING_ALGORITHM_NOT_ALLOWED, secpToken, secp, onlyEd25519);
  }

  @Test
  public void testExternalSigningAlgorithms() throws Exception {
    KeyPair secp = KeyPair.generate(Algorithm.SECP256R1, rng);
    Biscuit plain = authority(b -> b.addFact("a(1)"));
    byte[] token = thirdPartyToken(plain, secp).serialize();

    assertAccepted(
        token,
        DeserializationLimit.allowEverything()
            .setAllowedExternalSigningAlgorithms(Set.of(Algorithm.SECP256R1)));
    assertRejected(
        Reason.EXTERNAL_SIGNING_ALGORITHM_NOT_ALLOWED,
        token,
        DeserializationLimit.allowEverything()
            .setAllowedExternalSigningAlgorithms(Set.of(Algorithm.Ed25519)));
    // the internal algorithms don't restrict the third party keys
    assertAccepted(
        token,
        DeserializationLimit.allowEverything()
            .setAllowedInternalSigningAlgorithms(Set.of(Algorithm.Ed25519)));
  }

  @Test
  public void testMinSignatureVersion() throws Exception {
    KeyPair secp = KeyPair.generate(Algorithm.SECP256R1, rng);
    // blocks using only Ed25519 and old datalog features use version 0 signatures
    byte[] version0 = authority(b -> b.addFact("a(1)")).serialize();
    byte[] version1 = authorityWith(secp, b -> b.addFact("a(1)")).serialize();

    DeserializationLimit atLeast1 =
        DeserializationLimit.allowEverything().setMinSignatureVersion(1);
    assertAccepted(version0, DeserializationLimit.allowEverything().setMinSignatureVersion(0));
    assertAccepted(version1, secp, atLeast1);
    assertRejected(Reason.SIGNATURE_VERSION_TOO_LOW, version0, atLeast1);
  }

  @Test
  public void testMinSignatureVersionAboveTheHighestSupportedIsRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () -> DeserializationLimit.allowEverything().setMinSignatureVersion(2));
    assertDoesNotThrow(() -> DeserializationLimit.allowEverything().setMinSignatureVersion(1));
  }

  @Test
  public void testDeserializationLimitEqualsAndHashCode() {
    DeserializationLimit everything = DeserializationLimit.allowEverything();
    assertEquals(everything, DeserializationLimit.allowEverything());
    assertEquals(everything.hashCode(), DeserializationLimit.allowEverything().hashCode());
    assertEquals(DeserializationLimit.allowNothing(), DeserializationLimit.allowNothing());
    assertNotEquals(everything, DeserializationLimit.allowNothing());
    assertNotEquals(null, everything);
    assertNotEquals("not a limit", everything);

    // each kind of setting takes part in the comparison, including the nested per block limits
    DeserializationLimit changed = DeserializationLimit.allowEverything().setMaxBlocks(1);
    assertNotEquals(everything, changed);
    changed = DeserializationLimit.allowEverything().setAllowSealedTokens(false);
    assertNotEquals(everything, changed);
    changed =
        DeserializationLimit.allowEverything()
            .setAllowedInternalSigningAlgorithms(Set.of(Algorithm.Ed25519));
    assertNotEquals(everything, changed);
    changed = DeserializationLimit.allowEverything();
    changed.getAuthority().setMaxFacts(1);
    assertNotEquals(everything, changed);
    changed = DeserializationLimit.allowEverything();
    changed.getAttenuations().setAllowClosures(false);
    assertNotEquals(everything, changed);

    // and equal limits built in different ways are equal
    DeserializationLimit rebuilt = DeserializationLimit.allowEverything().setMaxBlocks(1);
    rebuilt.setMaxBlocks(Integer.MAX_VALUE);
    assertEquals(everything, rebuilt);
    assertEquals(everything.hashCode(), rebuilt.hashCode());
  }

  // equals and hashCode compare a list of the fields, so a field which is left out of that list
  // would
  // silently stop taking part in equality; this checks each field by reflection, so that includes
  // fields added in the future
  @Test
  public void testEveryFieldTakesPartInEquality() throws Exception {
    // for each class: a limit to change, an untouched limit to compare it to, and a source of
    // values
    Object[][] limits = {
      {
        DeserializationLimit.allowNothing(),
        DeserializationLimit.allowNothing(),
        DeserializationLimit.allowEverything()
      },
      {PerBlock.allowNothing(), PerBlock.allowNothing(), PerBlock.allowEverything()}
    };

    for (Object[] limit : limits) {
      Object changed = limit[0];
      Object untouched = limit[1];
      Object everything = limit[2];

      for (Field field : changed.getClass().getDeclaredFields()) {
        if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
          continue;
        }
        field.setAccessible(true);
        String name = changed.getClass().getSimpleName() + "." + field.getName();

        Object nothingValue = field.get(changed);
        Object everythingValue = field.get(everything);
        assertNotEquals(
            nothingValue,
            everythingValue,
            name + " is the same in allowNothing and allowEverything, so this test can't use it");

        // change only this field, and the limits must no longer be equal
        field.set(changed, everythingValue);
        assertNotEquals(untouched, changed, name + " is not used by equals");
        field.set(changed, nothingValue);
      }
      assertEquals(untouched, changed, "every field was put back");
    }
  }

  @Test
  public void testDeserializingABlockAddsItsSymbolsAndKeysToTheSymbolTable() throws Exception {
    KeyPair key = KeyPair.generate(Algorithm.Ed25519, rng);
    Block builder = new Block();
    builder.addFact("a(\"hello\")");
    builder.addCheck("check if b(1) trusting ed25519/" + key.getPublicKey().toHex());
    byte[] bytes = builder.build().toBytes().getOk();

    org.eclipse.biscuit.datalog.SymbolTable symbols = new org.eclipse.biscuit.datalog.SymbolTable();
    org.eclipse.biscuit.token.Block.fromBytes(
            bytes, Optional.empty(), PerBlock.allowEverything(), symbols)
        .getOk();

    assertTrue(symbols.symbols().contains("hello"));
    assertEquals(java.util.List.of(key.getPublicKey()), symbols.getPublicKeys());
  }

  @Test
  public void testOnlyBlocksWithoutExternalSignaturesAddToTheSharedSymbolTable() throws Exception {
    KeyPair external = KeyPair.generate(Algorithm.Ed25519, rng);
    Biscuit authority = authority(b -> b.addFact("authorityname(1)"));
    Biscuit attenuated =
        authority.attenuate(new Block().addFact("attenuationname(1)"), Algorithm.Ed25519);

    Block thirdParty = new Block();
    thirdParty.addFact("thirdpartyname(1)");
    ThirdPartyBlockContents contents =
        attenuated.thirdPartyRequest().createBlock(external, thirdParty).getOk();
    byte[] token = attenuated.appendThirdPartyBlock(external.getPublicKey(), contents).serialize();

    org.eclipse.biscuit.datalog.SymbolTable symbols = new org.eclipse.biscuit.datalog.SymbolTable();
    UnverifiedBiscuit.fromBytesWithSymbols(token, symbols);

    assertTrue(symbols.symbols().contains("authorityname"));
    assertTrue(symbols.symbols().contains("attenuationname"));
    // a third party block keeps its own symbols
    assertFalse(symbols.symbols().contains("thirdpartyname"));
  }

  @Test
  public void testTrustedScopeKindsAreComparedByTheirAlgorithm() {
    TrustedScopeKind ed25519 = TrustedScopeKind.publicKey(Algorithm.Ed25519);
    assertEquals(ed25519, TrustedScopeKind.publicKey(Algorithm.Ed25519));
    assertEquals(ed25519.hashCode(), TrustedScopeKind.publicKey(Algorithm.Ed25519).hashCode());
    assertFalse(ed25519.equals(TrustedScopeKind.publicKey(Algorithm.SECP256R1)));
    assertFalse(ed25519.equals(TrustedScopeKind.AUTHORITY));
    assertFalse(TrustedScopeKind.AUTHORITY.equals(TrustedScopeKind.PREVIOUS));
    assertTrue(Set.of(ed25519).contains(TrustedScopeKind.publicKey(Algorithm.Ed25519)));
    assertFalse(Set.of(ed25519).contains(TrustedScopeKind.publicKey(Algorithm.SECP256R1)));
    // every algorithm the protobuf defines has a kind, without this class having to list them
    for (Algorithm algorithm : Algorithm.values()) {
      assertNotNull(TrustedScopeKind.publicKey(algorithm));
    }
  }

  @Test
  public void testATermWithNoContentIsRejectedWithItsKindInTheMessage() {
    var result =
        org.eclipse.biscuit.datalog.Term.deserializeEnumV2(
            Schema.TermV2.getDefaultInstance(),
            PerBlock.allowEverything(),
            new org.eclipse.biscuit.datalog.SymbolTable());

    assertTrue(result.isErr());
    assertEquals(
        new Error.FormatError.DeserializationError("invalid Term kind: CONTENT_NOT_SET"),
        result.getErr());
  }

  @Test
  public void testNegativeLimitsAreRejected() {
    DeserializationLimit limit = DeserializationLimit.allowEverything();
    assertThrows(IllegalArgumentException.class, () -> limit.setMaxTokenSize(-1));
    assertThrows(IllegalArgumentException.class, () -> limit.setMaxBlocks(-1));
    assertThrows(IllegalArgumentException.class, () -> limit.setMinSignatureVersion(-1));
    assertThrows(IllegalArgumentException.class, () -> limit.getAuthority().setMaxFacts(-1));
    assertThrows(IllegalArgumentException.class, () -> limit.getAttenuations().setMaxBlockSize(-1));
    assertDoesNotThrow(() -> limit.setMaxBlocks(0));
  }

  @Test
  public void testTokenLevelLimitsAreCheckedBeforeSignatures() throws Exception {
    Biscuit token =
        authority(b -> b.addFact("a(1)")).attenuate(new Block().addFact("b(1)"), Algorithm.Ed25519);
    Schema.Biscuit.Builder tampered = Schema.Biscuit.parseFrom(token.serialize()).toBuilder();
    byte[] signature = tampered.getAuthority().getSignature().toByteArray();
    signature[0] ^= 1;
    tampered.getAuthorityBuilder().setSignature(ByteString.copyFrom(signature));
    byte[] bytes = tampered.build().toByteArray();

    // the tampering is noticed...
    assertThrows(
        Error.FormatError.Signature.class,
        () ->
            Biscuit.fromBytes(bytes, root.getPublicKey(), DeserializationLimit.allowEverything()));
    // ...unless the token violates a token level setting, which is checked first
    assertRejected(
        Reason.TOO_MANY_BLOCKS, bytes, DeserializationLimit.allowEverything().setMaxBlocks(1));
  }

  @Test
  public void testDeserializationLimitIsCheckedBeforeLookingUpTheRootKey() throws Exception {
    byte[] token = authority(b -> b.addFact("a(1)")).serialize();
    AtomicInteger lookups = new AtomicInteger();
    KeyDelegate delegate =
        keyId -> {
          lookups.incrementAndGet();
          return Optional.of(root.getPublicKey());
        };

    assertThrows(
        Error.FormatError.DeserializationLimitError.class,
        () ->
            Biscuit.fromBytes(
                token, delegate, DeserializationLimit.allowEverything().setMaxBlocks(0)));
    assertEquals(0, lookups.get());
    Biscuit.fromBytes(token, delegate, DeserializationLimit.allowEverything());
    assertEquals(1, lookups.get());
  }

  @Test
  public void testUnverifiedBiscuitChecksTheDeserializationLimit() throws Exception {
    byte[] token = authority(b -> b.addFact("a(1)")).serialize();
    String base64 = Biscuit.fromBytes(token, root.getPublicKey()).serializeBase64Url();

    DeserializationLimit noFacts = DeserializationLimit.allowEverything();
    noFacts.getAuthority().setMaxFacts(0);
    assertThrows(
        Error.FormatError.DeserializationLimitError.class,
        () -> UnverifiedBiscuit.fromBytes(token, noFacts));
    assertThrows(
        Error.FormatError.DeserializationLimitError.class,
        () -> UnverifiedBiscuit.fromBase64Url(base64, noFacts));
    assertThrows(
        Error.FormatError.DeserializationLimitError.class,
        () -> Biscuit.fromBase64Url(base64, root.getPublicKey(), noFacts));
    assertDoesNotThrow(
        () -> UnverifiedBiscuit.fromBytes(token, DeserializationLimit.allowEverything()));
  }

  @Test
  public void testAuthorityAndAttenuationsHaveSeparateLimits() throws Exception {
    byte[] token =
        authority(b -> b.addFact("a(1)").addFact("a(2)"))
            .attenuate(new Block().addFact("b(1)").addFact("b(2)"), Algorithm.Ed25519)
            .serialize();

    DeserializationLimit limitsAuthority = DeserializationLimit.allowEverything();
    limitsAuthority.getAuthority().setMaxFacts(1);
    DeserializationLimit limitsAttenuations = DeserializationLimit.allowEverything();
    limitsAttenuations.getAttenuations().setMaxFacts(1);
    DeserializationLimit limitsNeither = DeserializationLimit.allowEverything();
    limitsNeither.getAuthority().setMaxFacts(2);
    limitsNeither.getAttenuations().setMaxFacts(2);

    assertRejected(Reason.TOO_MANY_FACTS, token, limitsAuthority);
    assertRejected(Reason.TOO_MANY_FACTS, token, limitsAttenuations);
    assertAccepted(token, limitsNeither);
  }

  @Test
  public void testMaxBlockSize() throws Exception {
    assertBlockLimit(
        Reason.BLOCK_TOO_LARGE,
        b -> b.addFact("a(\"a string that makes the block larger than the limit\")"),
        p -> p.setMaxBlockSize(30));
  }

  @Test
  public void testMaxFacts() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_FACTS, b -> b.addFact("a(1)").addFact("a(2)"), p -> p.setMaxFacts(1));
  }

  @Test
  public void testMaxRules() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_RULES,
        b -> b.addRule("r($x) <- f($x)").addRule("s($x) <- f($x)"),
        p -> p.setMaxRules(1));
  }

  @Test
  public void testMaxChecks() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_CHECKS,
        b -> b.addCheck("check if a(1)").addCheck("reject if b(1)"),
        p -> p.setMaxChecks(1));
  }

  @Test
  public void testMaxSymbols() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_SYMBOLS,
        b -> b.addFact("a(\"one\", \"two\", \"three\")"),
        p -> p.setMaxSymbols(2));
  }

  @Test
  public void testMaxPublicKeys() throws Exception {
    KeyPair key = KeyPair.generate(Algorithm.Ed25519, rng);
    assertBlockLimit(
        Reason.TOO_MANY_PUBLIC_KEYS,
        b -> b.addCheck("check if a(1) trusting ed25519/" + key.getPublicKey().toHex()),
        p -> p.setMaxPublicKeys(0));
  }

  @Test
  public void testMaxContextLength() throws Exception {
    assertBlockLimit(
        Reason.CONTEXT_TOO_LONG, b -> b.setContext("four"), p -> p.setMaxContextLength(3));
  }

  @Test
  public void testMaxQueriesPerCheck() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_QUERIES,
        b -> b.addCheck("check if a(1) or b(1)"),
        p -> p.setMaxQueriesPerCheck(1));
  }

  @Test
  public void testMaxPredicatesPerBody() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_PREDICATES,
        b -> b.addCheck("check if a(1), b(1)"),
        p -> p.setMaxPredicatesPerBody(1));
    assertBlockLimit(
        Reason.TOO_MANY_PREDICATES,
        b -> b.addRule("r($x) <- a($x), b($x)"),
        p -> p.setMaxPredicatesPerBody(1));
  }

  @Test
  public void testMaxExpressionsPerBody() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_EXPRESSIONS,
        b -> b.addCheck("check if a($x), $x > 1, $x < 5"),
        p -> p.setMaxExpressionsPerBody(1));
    assertBlockLimit(
        Reason.TOO_MANY_EXPRESSIONS,
        b -> b.addRule("r($x) <- a($x), $x > 1, $x < 5"),
        p -> p.setMaxExpressionsPerBody(1));
  }

  @Test
  public void testMaxOpsPerExpression() throws Exception {
    // 1 2 + 3 + 5 > is seven ops
    BlockSetup sevenOps = b -> b.addCheck("check if 1 + 2 + 3 > 5");
    assertBlockLimit(Reason.TOO_MANY_OPS, sevenOps, p -> p.setMaxOpsPerExpression(6));
    assertAccepted(
        authority(sevenOps).serialize(), authorityLimits(p -> p.setMaxOpsPerExpression(7)));
  }

  @Test
  public void testOpsInClosuresCountTowardsTheirExpression() throws Exception {
    // [1] (closure: $x 0 >) all is six ops once the closure's own ops are counted
    BlockSetup closure = b -> b.addCheck("check if [1].all($x -> $x > 0)");
    assertBlockLimit(Reason.TOO_MANY_OPS, closure, p -> p.setMaxOpsPerExpression(5));
    assertAccepted(
        authority(closure).serialize(), authorityLimits(p -> p.setMaxOpsPerExpression(6)));
  }

  @Test
  public void testMaxTermsPerPredicate() throws Exception {
    assertBlockLimit(
        Reason.TOO_MANY_TERMS, b -> b.addFact("a(1, 2, 3)"), p -> p.setMaxTermsPerPredicate(2));
    assertBlockLimit(
        Reason.TOO_MANY_TERMS,
        b -> b.addCheck("check if a(1, 2, 3)"),
        p -> p.setMaxTermsPerPredicate(2));
  }

  @Test
  public void testMaxNameLength() throws Exception {
    // predicate names
    assertBlockLimit(
        Reason.NAME_TOO_LONG, b -> b.addFact("long_name(1)"), p -> p.setMaxNameLength(5));
    // variable names
    assertBlockLimit(
        Reason.NAME_TOO_LONG,
        b -> b.addCheck("check if a($long_name)"),
        p -> p.setMaxNameLength(5));
    // closure parameter names
    assertBlockLimit(
        Reason.NAME_TOO_LONG,
        b -> b.addCheck("check if [1].all($a -> $a > 0) or [1].all($long_name -> $long_name > 0)"),
        p -> p.setMaxNameLength(5));
    // string values are not names
    assertAccepted(
        authority(b -> b.addFact("a(\"long string\")")).serialize(),
        authorityLimits(p -> p.setMaxNameLength(5)));
  }

  @Test
  public void testMaxStringLengthIsMeasuredInBytes() throws Exception {
    // each of these characters is two bytes in UTF-8
    BlockSetup string = b -> b.addFact("a(\"\u00e9\u00e9\u00e9\")");
    assertBlockLimit(Reason.STRING_TOO_LONG, string, p -> p.setMaxStringLength(5));
    assertAccepted(authority(string).serialize(), authorityLimits(p -> p.setMaxStringLength(6)));
  }

  @Test
  public void testNamesDefinedInEarlierBlocksAreChecked() throws Exception {
    byte[] token =
        authority(b -> b.addFact("long_name(1)"))
            .attenuate(new Block().addCheck("check if long_name(1)"), Algorithm.Ed25519)
            .serialize();
    // the attenuation refers to a symbol from the authority block
    DeserializationLimit limitsAttenuations = DeserializationLimit.allowEverything();
    limitsAttenuations.getAttenuations().setMaxNameLength(5);
    assertRejected(Reason.NAME_TOO_LONG, token, limitsAttenuations);
    DeserializationLimit limitsAuthority = DeserializationLimit.allowEverything();
    limitsAuthority.getAuthority().setMaxNameLength(5);
    assertRejected(Reason.NAME_TOO_LONG, token, limitsAuthority);
  }

  @Test
  public void testMaxStringLength() throws Exception {
    assertBlockLimit(
        Reason.STRING_TOO_LONG, b -> b.addFact("a(\"abcd\")"), p -> p.setMaxStringLength(3));
    assertBlockLimit(
        Reason.STRING_TOO_LONG, b -> b.addFact("a({\"abcd\": 1})"), p -> p.setMaxStringLength(3));
    // names are not strings
    assertAccepted(
        authority(b -> b.addFact("long_name(1)")).serialize(),
        authorityLimits(p -> p.setMaxStringLength(3)));
  }

  @Test
  public void testMaxBytesLength() throws Exception {
    assertBlockLimit(
        Reason.BYTES_TOO_LONG, b -> b.addFact("a(hex:010203)"), p -> p.setMaxBytesLength(2));
  }

  @Test
  public void testMaxCollectionLengths() throws Exception {
    assertBlockLimit(
        Reason.SET_TOO_LONG, b -> b.addFact("a({1, 2, 3})"), p -> p.setMaxSetLength(2));
    assertBlockLimit(
        Reason.ARRAY_TOO_LONG, b -> b.addFact("a([1, 2, 3])"), p -> p.setMaxArrayLength(2));
    assertBlockLimit(
        Reason.MAP_TOO_LONG, b -> b.addFact("a({1: 1, 2: 2, 3: 3})"), p -> p.setMaxMapLength(2));
    // the limits only apply to their own kind of collection
    assertAccepted(
        authority(b -> b.addFact("a([1, 2, 3])")).serialize(),
        authorityLimits(p -> p.setMaxSetLength(0).setMaxMapLength(0)));
  }

  @Test
  public void testNestedCollectionsAreChecked() throws Exception {
    assertBlockLimit(
        Reason.ARRAY_TOO_LONG,
        b -> b.addFact("a({\"k\": [1, 2, 3]})"),
        p -> p.setMaxArrayLength(2));
  }

  @Test
  public void testClosures() throws Exception {
    assertBlockLimit(
        Reason.CLOSURES_NOT_ALLOWED,
        b -> b.addCheck("check if [1].all($x -> $x > 0)"),
        p -> p.setAllowClosures(false));
    assertAccepted(
        authority(b -> b.addCheck("check if 1 > 0")).serialize(),
        authorityLimits(p -> p.setAllowClosures(false)));
  }

  @Test
  public void testBinaryOperations() throws Exception {
    Set<Op.BinaryOp> allButRegex = EnumSet.complementOf(EnumSet.of(Op.BinaryOp.Regex));
    assertBlockLimit(
        Reason.BINARY_OPERATION_NOT_ALLOWED,
        b -> b.addCheck("check if \"abc\".matches(\"a+\")"),
        p -> p.setAllowedBinaryOps(allButRegex));
    assertAccepted(
        authority(b -> b.addCheck("check if \"abc\".starts_with(\"a\")")).serialize(),
        authorityLimits(p -> p.setAllowedBinaryOps(allButRegex)));
    assertBlockLimit(
        Reason.BINARY_OPERATION_NOT_ALLOWED,
        b -> b.addCheck("check if 1 + 2 > 0"),
        p -> p.setAllowedBinaryOps(Set.of(Op.BinaryOp.Add)));
  }

  @Test
  public void testUnaryOperations() throws Exception {
    assertBlockLimit(
        Reason.UNARY_OPERATION_NOT_ALLOWED,
        b -> b.addCheck("check if !false"),
        p -> p.setAllowedUnaryOps(Set.of(Op.UnaryOp.Length)));
    assertAccepted(
        authority(b -> b.addCheck("check if \"abc\".length() > 1")).serialize(),
        authorityLimits(
            p ->
                p.setAllowedUnaryOps(Set.of(Op.UnaryOp.Length))
                    .setAllowedBinaryOps(Set.of(Op.BinaryOp.GreaterThan))));
  }

  @Test
  public void testTermTypes() throws Exception {
    Set<TermType> onlyIntegers = Set.of(TermType.INTEGER);
    assertBlockLimit(
        Reason.TERM_TYPE_NOT_ALLOWED,
        b -> b.addFact("a(\"string\")"),
        p -> p.setAllowedTermTypes(onlyIntegers));
    // types of terms inside collections and expressions are checked too
    assertBlockLimit(
        Reason.TERM_TYPE_NOT_ALLOWED,
        b -> b.addFact("a([true])"),
        p -> p.setAllowedTermTypes(Set.of(TermType.ARRAY, TermType.INTEGER)));
    assertBlockLimit(
        Reason.TERM_TYPE_NOT_ALLOWED,
        b -> b.addCheck("check if 1 < 2 || null == null"),
        p -> p.setAllowedTermTypes(onlyIntegers));
    // variables are not values
    assertAccepted(
        authority(b -> b.addCheck("check if a($x), $x > 0")).serialize(),
        authorityLimits(p -> p.setAllowedTermTypes(onlyIntegers)));
  }

  @Test
  public void testMapKeyTypes() throws Exception {
    assertBlockLimit(
        Reason.MAP_KEY_TYPE_NOT_ALLOWED,
        b -> b.addFact("a({\"key\": 1})"),
        p -> p.setAllowedMapKeyTypes(Set.of(MapKeyType.INTEGER)));
    assertAccepted(
        authority(b -> b.addFact("a({1: 1})")).serialize(),
        authorityLimits(p -> p.setAllowedMapKeyTypes(Set.of(MapKeyType.INTEGER))));
  }

  @Test
  public void testCheckKinds() throws Exception {
    Set<Check.Kind> onlyOne = Set.of(Check.Kind.ONE);
    assertBlockLimit(
        Reason.CHECK_KIND_NOT_ALLOWED,
        b -> b.addCheck("check all a($x), $x > 0"),
        p -> p.setAllowedCheckKinds(onlyOne));
    assertBlockLimit(
        Reason.CHECK_KIND_NOT_ALLOWED,
        b -> b.addCheck("reject if a(1)"),
        p -> p.setAllowedCheckKinds(onlyOne));
    assertAccepted(
        authority(b -> b.addCheck("check if a(1)")).serialize(),
        authorityLimits(p -> p.setAllowedCheckKinds(onlyOne)));
  }

  @Test
  public void testTrustedScopes() throws Exception {
    KeyPair key = KeyPair.generate(Algorithm.Ed25519, rng);
    String publicKey = "ed25519/" + key.getPublicKey().toHex();
    Set<TrustedScopeKind> onlyAuthority = Set.of(TrustedScopeKind.AUTHORITY);

    // scopes of a check query, of a rule and of the block itself
    assertBlockLimit(
        Reason.TRUSTED_SCOPE_NOT_ALLOWED,
        b -> b.addCheck("check if a(1) trusting previous"),
        p -> p.setAllowedTrustingScopes(onlyAuthority));
    assertBlockLimit(
        Reason.TRUSTED_SCOPE_NOT_ALLOWED,
        b -> b.addRule("r($x) <- a($x) trusting previous"),
        p -> p.setAllowedTrustingScopes(onlyAuthority));
    assertBlockLimit(
        Reason.TRUSTED_SCOPE_NOT_ALLOWED,
        b -> b.addScope(org.eclipse.biscuit.token.builder.Scope.previous()),
        p -> p.setAllowedTrustingScopes(onlyAuthority));
    assertAccepted(
        authority(b -> b.addCheck("check if a(1) trusting authority")).serialize(),
        authorityLimits(p -> p.setAllowedTrustingScopes(onlyAuthority)));

    // the algorithm of a public key is looked up in the block's public keys
    BlockSetup trustsKey = b -> b.addCheck("check if a(1) trusting " + publicKey);
    assertBlockLimit(
        Reason.TRUSTED_SCOPE_NOT_ALLOWED,
        trustsKey,
        p ->
            p.setAllowedTrustingScopes(
                Set.of(
                    TrustedScopeKind.AUTHORITY,
                    TrustedScopeKind.PREVIOUS,
                    TrustedScopeKind.publicKey(Algorithm.SECP256R1))));
    assertAccepted(
        authority(trustsKey).serialize(),
        authorityLimits(
            p ->
                p.setAllowedTrustingScopes(Set.of(TrustedScopeKind.publicKey(Algorithm.Ed25519)))));
  }

  @Test
  public void testPublicKeysFromEarlierBlocksCanBeTrusted() throws Exception {
    KeyPair key = KeyPair.generate(Algorithm.Ed25519, rng);
    String publicKey = "ed25519/" + key.getPublicKey().toHex();
    // the attenuation refers to the key through the authority block's public key table
    byte[] token =
        authority(b -> b.addCheck("check if a(1) trusting " + publicKey))
            .attenuate(
                new Block().addCheck("check if b(1) trusting " + publicKey), Algorithm.Ed25519)
            .serialize();

    DeserializationLimit onlyEd25519 = DeserializationLimit.allowEverything();
    onlyEd25519
        .getAuthority()
        .setAllowedTrustingScopes(Set.of(TrustedScopeKind.publicKey(Algorithm.Ed25519)));
    onlyEd25519
        .getAttenuations()
        .setAllowedTrustingScopes(Set.of(TrustedScopeKind.publicKey(Algorithm.Ed25519)));
    DeserializationLimit onlyAuthority = DeserializationLimit.allowEverything();
    onlyAuthority.getAttenuations().setAllowedTrustingScopes(Set.of(TrustedScopeKind.AUTHORITY));

    assertAccepted(token, onlyEd25519);
    assertRejected(Reason.TRUSTED_SCOPE_NOT_ALLOWED, token, onlyAuthority);
  }

  @Test
  public void testThirdPartyBlocksAreChecked() throws Exception {
    KeyPair external = KeyPair.generate(Algorithm.Ed25519, rng);
    byte[] token = thirdPartyToken(authority(b -> b.addFact("a(1)")), external).serialize();

    // thirdPartyToken's block has two facts and uses its own symbol table
    DeserializationLimit limitsFacts = DeserializationLimit.allowEverything();
    limitsFacts.getAttenuations().setMaxFacts(1);
    DeserializationLimit limitsNames = DeserializationLimit.allowEverything();
    limitsNames.getAttenuations().setMaxNameLength(3);
    assertRejected(Reason.TOO_MANY_FACTS, token, limitsFacts);
    assertRejected(Reason.NAME_TOO_LONG, token, limitsNames);
    limitsFacts.getAttenuations().setMaxFacts(2);
    limitsNames.getAttenuations().setMaxNameLength(5);
    assertAccepted(token, limitsFacts);
    assertAccepted(token, limitsNames);
  }

  @Test
  public void testSettersCopyTheirSets() {
    Set<Check.Kind> kinds = EnumSet.of(Check.Kind.ONE);
    PerBlock perBlock = PerBlock.allowEverything().setAllowedCheckKinds(kinds);
    kinds.add(Check.Kind.ALL);
    assertEquals(Set.of(Check.Kind.ONE), perBlock.getAllowedCheckKinds());
    assertNull(PerBlock.allowEverything().getAllowedCheckKinds());
    assertEquals(PerBlock.allowEverything(), PerBlock.allowEverything());
    assertFalse(PerBlock.allowEverything().equals(PerBlock.allowNothing()));
  }

  /**
   * Checks that a limit applies to the authority block and to attenuations, and only to the block
   * it is set for
   */
  private void assertBlockLimit(Reason reason, BlockSetup setup, Consumer<PerBlock> restrict)
      throws Exception {
    // in the authority block
    byte[] authorityToken = authority(setup).serialize();
    assertRejected(reason, authorityToken, authorityLimits(restrict));
    assertAccepted(authorityToken, attenuationLimits(restrict));

    // in an attenuation block
    Block attenuation = new Block();
    setup.apply(attenuation);
    byte[] attenuatedToken =
        authority(b -> b.addFact("base(1)")).attenuate(attenuation, Algorithm.Ed25519).serialize();
    assertRejected(reason, attenuatedToken, attenuationLimits(restrict));
    assertAccepted(attenuatedToken, authorityLimits(restrict));
  }

  private static DeserializationLimit authorityLimits(Consumer<PerBlock> restrict) {
    DeserializationLimit deserializationLimit = DeserializationLimit.allowEverything();
    restrict.accept(deserializationLimit.getAuthority());
    return deserializationLimit;
  }

  private static DeserializationLimit attenuationLimits(Consumer<PerBlock> restrict) {
    DeserializationLimit deserializationLimit = DeserializationLimit.allowEverything();
    restrict.accept(deserializationLimit.getAttenuations());
    return deserializationLimit;
  }

  private Biscuit authority(BlockSetup setup) throws Exception {
    return authorityWith(root, setup);
  }

  private Biscuit authorityWith(KeyPair key, BlockSetup setup) throws Exception {
    Block block = new Block();
    setup.apply(block);
    return Biscuit.make(rng, key, block.build());
  }

  /** Appends a block with two facts, signed by the external key, to the token */
  private Biscuit thirdPartyToken(Biscuit token, KeyPair external) throws Exception {
    Block block = new Block();
    block.addFact("group(\"admin\")");
    block.addFact("other(1)");
    ThirdPartyBlockContents contents =
        token.thirdPartyRequest().createBlock(external, block).getOk();
    return token.appendThirdPartyBlock(external.getPublicKey(), contents);
  }

  private void assertAccepted(byte[] token, DeserializationLimit deserializationLimit)
      throws Exception {
    assertAccepted(token, root, deserializationLimit);
  }

  private void assertAccepted(
      byte[] token, KeyPair rootKey, DeserializationLimit deserializationLimit) throws Exception {
    assertDoesNotThrow(
        () -> Biscuit.fromBytes(token, rootKey.getPublicKey(), deserializationLimit));
    assertDoesNotThrow(() -> UnverifiedBiscuit.fromBytes(token, deserializationLimit));
  }

  private void assertRejected(
      Reason reason, byte[] token, DeserializationLimit deserializationLimit) {
    assertRejected(reason, token, root, deserializationLimit);
  }

  private void assertRejected(
      Reason reason, byte[] token, KeyPair rootKey, DeserializationLimit deserializationLimit) {
    Error.FormatError.DeserializationLimitError verified =
        assertThrows(
            Error.FormatError.DeserializationLimitError.class,
            () -> Biscuit.fromBytes(token, rootKey.getPublicKey(), deserializationLimit));
    assertEquals(reason, verified.getReason());
    Error.FormatError.DeserializationLimitError unverified =
        assertThrows(
            Error.FormatError.DeserializationLimitError.class,
            () -> UnverifiedBiscuit.fromBytes(token, deserializationLimit));
    assertEquals(reason, unverified.getReason());
  }
}
