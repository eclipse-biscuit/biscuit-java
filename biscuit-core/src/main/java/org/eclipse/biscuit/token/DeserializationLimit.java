/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import biscuit.format.schema.Schema.PublicKey.Algorithm;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.eclipse.biscuit.datalog.Check;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.datalog.Term;
import org.eclipse.biscuit.datalog.expressions.Op;
import org.eclipse.biscuit.error.Error;

/**
 * Restrictions on the features a token may contain, enforced while the token is deserialized.
 *
 * <p>Settings which apply to the token as a whole are properties of the DeserializationLimit
 * itself, while settings which apply within each block are part of a {@link PerBlock} limit.
 * Separate {@link PerBlock} limits are used for the authority block and for attenuations, so that
 * attenuations can be restricted more tightly than the authority block.
 *
 * <p>Booleans and sets are "allow" settings: a boolean set to {@code false} forbids the feature,
 * and a set restricts the feature to its members, with {@code null} meaning that any member is
 * permitted. Integers are limits, with {@link Integer#MAX_VALUE} meaning unlimited, except for
 * {@code minSignatureVersion}, where {@code 0} accepts every version.
 *
 * <p>A new limit allows nothing: every setting starts at its most restrictive value. Start from
 * {@link #allowEverything()}, which allows everything, and restrict only the features you need to:
 *
 * <pre>{@code
 * DeserializationLimit limit = DeserializationLimit.allowEverything().setMaxBlocks(4);
 * limit.getAttenuations().setAllowClosures(false);
 * }</pre>
 *
 * <p>Alternatively, start from {@link #allowNothing()} and enable only the features you need.
 *
 * <p>A token which violates the limits is rejected with an {@link
 * org.eclipse.biscuit.error.Error.FormatError.DeserializationLimitError}. The settings for the
 * token as a whole (its size, number of blocks, sealing, signing algorithms, signature versions and
 * external signatures) are checked before any signature is verified. The settings within each
 * block are checked as the block is deserialized, which for a verified {@code Biscuit} is after its
 * signatures have been verified. A DeserializationLimit is mutable and should not be modified while
 * it is being used to deserialize a token.
 */
public final class DeserializationLimit {
  private boolean allowAttenuationsWithExternalSignatures = false;
  private boolean allowAttenuationsWithoutExternalSignatures = false;
  private boolean allowSealedTokens = false;
  private boolean allowUnsealedTokens = false;
  private int maxTokenSize = 0;
  private int maxBlocks = 0;
  private int minSignatureVersion = HIGHEST_SIGNATURE_VERSION;
  private Set<Algorithm> allowedInternalSigningAlgorithms = Set.of();
  private Set<Algorithm> allowedExternalSigningAlgorithms = Set.of();
  private PerBlock authority = PerBlock.allowNothing();
  private PerBlock attenuations = PerBlock.allowNothing();

  private DeserializationLimit() {}

  public static DeserializationLimit allowEverything() {
    DeserializationLimit deserializationLimit = new DeserializationLimit();
    deserializationLimit.allowAttenuationsWithExternalSignatures = true;
    deserializationLimit.allowAttenuationsWithoutExternalSignatures = true;
    deserializationLimit.allowSealedTokens = true;
    deserializationLimit.allowUnsealedTokens = true;
    deserializationLimit.maxTokenSize = Integer.MAX_VALUE;
    deserializationLimit.maxBlocks = Integer.MAX_VALUE;
    deserializationLimit.minSignatureVersion = 0;
    deserializationLimit.allowedInternalSigningAlgorithms = null;
    deserializationLimit.allowedExternalSigningAlgorithms = null;
    deserializationLimit.authority = PerBlock.allowEverything();
    deserializationLimit.attenuations = PerBlock.allowEverything();
    return deserializationLimit;
  }

  public static DeserializationLimit allowNothing() {
    return new DeserializationLimit();
  }

  private static final int HIGHEST_SIGNATURE_VERSION = 1;

  public boolean getAllowAttenuationsWithExternalSignatures() {
    return allowAttenuationsWithExternalSignatures;
  }

  public DeserializationLimit setAllowAttenuationsWithExternalSignatures(boolean allow) {
    this.allowAttenuationsWithExternalSignatures = allow;
    return this;
  }

  public boolean getAllowAttenuationsWithoutExternalSignatures() {
    return allowAttenuationsWithoutExternalSignatures;
  }

  public DeserializationLimit setAllowAttenuationsWithoutExternalSignatures(boolean allow) {
    this.allowAttenuationsWithoutExternalSignatures = allow;
    return this;
  }

  public boolean getAllowSealedTokens() {
    return allowSealedTokens;
  }

  public DeserializationLimit setAllowSealedTokens(boolean allow) {
    this.allowSealedTokens = allow;
    return this;
  }

  public boolean getAllowUnsealedTokens() {
    return allowUnsealedTokens;
  }

  public DeserializationLimit setAllowUnsealedTokens(boolean allow) {
    this.allowUnsealedTokens = allow;
    return this;
  }

  public int getMaxTokenSize() {
    return maxTokenSize;
  }

  public DeserializationLimit setMaxTokenSize(int max) {
    this.maxTokenSize = nonNegative(max);
    return this;
  }

  public int getMaxBlocks() {
    return maxBlocks;
  }

  public DeserializationLimit setMaxBlocks(int max) {
    this.maxBlocks = nonNegative(max);
    return this;
  }

  public int getMinSignatureVersion() {
    return minSignatureVersion;
  }

  public DeserializationLimit setMinSignatureVersion(int min) {
    if (min > HIGHEST_SIGNATURE_VERSION) {
      throw new IllegalArgumentException(
          "the minimum signature version "
              + min
              + " is higher than the highest supported version "
              + HIGHEST_SIGNATURE_VERSION);
    }
    this.minSignatureVersion = nonNegative(min);
    return this;
  }

  public Set<Algorithm> getAllowedInternalSigningAlgorithms() {
    return allowedInternalSigningAlgorithms;
  }

  public DeserializationLimit setAllowedInternalSigningAlgorithms(Set<Algorithm> algorithms) {
    this.allowedInternalSigningAlgorithms = copy(algorithms);
    return this;
  }

  public Set<Algorithm> getAllowedExternalSigningAlgorithms() {
    return allowedExternalSigningAlgorithms;
  }

  public DeserializationLimit setAllowedExternalSigningAlgorithms(Set<Algorithm> algorithms) {
    this.allowedExternalSigningAlgorithms = copy(algorithms);
    return this;
  }

  public PerBlock getAuthority() {
    return authority;
  }

  public DeserializationLimit setAuthority(PerBlock authority) {
    this.authority = Objects.requireNonNull(authority);
    return this;
  }

  public PerBlock getAttenuations() {
    return attenuations;
  }

  public DeserializationLimit setAttenuations(PerBlock attenuations) {
    this.attenuations = Objects.requireNonNull(attenuations);
    return this;
  }

  private static int nonNegative(int value) {
    if (value < 0) {
      throw new IllegalArgumentException("a limit cannot be negative: " + value);
    }
    return value;
  }

  private static <T> Set<T> copy(Set<T> set) {
    return set == null ? null : Set.copyOf(set);
  }

  private Object[] state() {
    return new Object[] {
      allowAttenuationsWithExternalSignatures,
      allowAttenuationsWithoutExternalSignatures,
      allowSealedTokens,
      allowUnsealedTokens,
      maxTokenSize,
      maxBlocks,
      minSignatureVersion,
      allowedInternalSigningAlgorithms,
      allowedExternalSigningAlgorithms,
      authority,
      attenuations
    };
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    return Arrays.equals(state(), ((DeserializationLimit) o).state());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(state());
  }

  public static final class TrustedScopeKind {
    private enum Kind {
      AUTHORITY,
      PREVIOUS,
      PUBLIC_KEY
    }

    public static final TrustedScopeKind AUTHORITY = new TrustedScopeKind(Kind.AUTHORITY, null);
    public static final TrustedScopeKind PREVIOUS = new TrustedScopeKind(Kind.PREVIOUS, null);

    private final Kind kind;
    private final Algorithm algorithm;

    private TrustedScopeKind(Kind kind, Algorithm algorithm) {
      this.kind = kind;
      this.algorithm = algorithm;
    }

    public static TrustedScopeKind publicKey(Algorithm algorithm) {
      return new TrustedScopeKind(Kind.PUBLIC_KEY, Objects.requireNonNull(algorithm));
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      TrustedScopeKind that = (TrustedScopeKind) o;
      return kind == that.kind && algorithm == that.algorithm;
    }

    @Override
    public int hashCode() {
      return Objects.hash(kind, algorithm);
    }

    @Override
    public String toString() {
      return kind == Kind.PUBLIC_KEY ? kind + "(" + algorithm + ")" : kind.toString();
    }
  }

  public static final class PerBlock {
    private boolean allowClosures = false;
    private int maxBlockSize = 0;
    private int maxFacts = 0;
    private int maxRules = 0;
    private int maxChecks = 0;
    private int maxSymbols = 0;
    private int maxPublicKeys = 0;
    private int maxContextLength = 0;
    private int maxQueriesPerCheck = 0;
    private int maxPredicatesPerBody = 0;
    private int maxExpressionsPerBody = 0;
    private int maxOpsPerExpression = 0;
    private int maxTermsPerPredicate = 0;
    private int maxNameLength = 0;
    private int maxBytesLength = 0;
    private int maxStringLength = 0;
    private int maxSetLength = 0;
    private int maxArrayLength = 0;
    private int maxMapLength = 0;
    private Set<Op.BinaryOp> allowedBinaryOps = Set.of();
    private Set<Op.UnaryOp> allowedUnaryOps = Set.of();
    private Set<String> allowedUnaryExternalFunctions = Set.of();
    private Set<String> allowedBinaryExternalFunctions = Set.of();
    private Set<Term.TermType> allowedTermTypes = Set.of();
    private Set<Term.MapKeyType> allowedMapKeyTypes = Set.of();
    private Set<TrustedScopeKind> allowedTrustingScopes = Set.of();
    private Set<Check.Kind> allowedCheckKinds = Set.of();

    private PerBlock() {}

    public static PerBlock allowEverything() {
      PerBlock perBlock = new PerBlock();
      perBlock.allowClosures = true;
      perBlock.maxBlockSize = Integer.MAX_VALUE;
      perBlock.maxFacts = Integer.MAX_VALUE;
      perBlock.maxRules = Integer.MAX_VALUE;
      perBlock.maxChecks = Integer.MAX_VALUE;
      perBlock.maxSymbols = Integer.MAX_VALUE;
      perBlock.maxPublicKeys = Integer.MAX_VALUE;
      perBlock.maxContextLength = Integer.MAX_VALUE;
      perBlock.maxQueriesPerCheck = Integer.MAX_VALUE;
      perBlock.maxPredicatesPerBody = Integer.MAX_VALUE;
      perBlock.maxExpressionsPerBody = Integer.MAX_VALUE;
      perBlock.maxOpsPerExpression = Integer.MAX_VALUE;
      perBlock.maxTermsPerPredicate = Integer.MAX_VALUE;
      perBlock.maxNameLength = Integer.MAX_VALUE;
      perBlock.maxBytesLength = Integer.MAX_VALUE;
      perBlock.maxStringLength = Integer.MAX_VALUE;
      perBlock.maxSetLength = Integer.MAX_VALUE;
      perBlock.maxArrayLength = Integer.MAX_VALUE;
      perBlock.maxMapLength = Integer.MAX_VALUE;
      perBlock.allowedBinaryOps = null;
      perBlock.allowedUnaryOps = null;
      perBlock.allowedUnaryExternalFunctions = null;
      perBlock.allowedBinaryExternalFunctions = null;
      perBlock.allowedTermTypes = null;
      perBlock.allowedMapKeyTypes = null;
      perBlock.allowedTrustingScopes = null;
      perBlock.allowedCheckKinds = null;
      return perBlock;
    }

    public static PerBlock allowNothing() {
      return new PerBlock();
    }

    public Error.FormatError checkName(SymbolTable symbols, long symbolIndex) {
      return checkLength(
          symbols,
          symbolIndex,
          maxNameLength,
          Error.FormatError.DeserializationLimitError.Reason.NAME_TOO_LONG);
    }

    public Error.FormatError checkString(SymbolTable symbols, long symbolIndex) {
      return checkLength(
          symbols,
          symbolIndex,
          maxStringLength,
          Error.FormatError.DeserializationLimitError.Reason.STRING_TOO_LONG);
    }

    private static Error.FormatError checkLength(
        SymbolTable symbols,
        long symbolIndex,
        int maxLength,
        Error.FormatError.DeserializationLimitError.Reason reason) {
      // a symbol must always be known when it is referenced, whatever the limits are
      Optional<String> symbol =
          symbolIndex >= 0 && symbolIndex <= Integer.MAX_VALUE
              ? symbols.getSymbol((int) symbolIndex)
              : Optional.empty();
      if (symbol.isEmpty()) {
        return new Error.FormatError.UnknownSymbol(symbolIndex);
      }
      if (maxLength == Integer.MAX_VALUE) {
        return null;
      }
      if (symbol.get().getBytes(StandardCharsets.UTF_8).length > maxLength) {
        return new Error.FormatError.DeserializationLimitError(reason);
      }
      return null;
    }

    public boolean getAllowClosures() {
      return allowClosures;
    }

    public PerBlock setAllowClosures(boolean allow) {
      this.allowClosures = allow;
      return this;
    }

    public int getMaxBlockSize() {
      return maxBlockSize;
    }

    public PerBlock setMaxBlockSize(int max) {
      this.maxBlockSize = nonNegative(max);
      return this;
    }

    public int getMaxFacts() {
      return maxFacts;
    }

    public PerBlock setMaxFacts(int max) {
      this.maxFacts = nonNegative(max);
      return this;
    }

    public int getMaxRules() {
      return maxRules;
    }

    public PerBlock setMaxRules(int max) {
      this.maxRules = nonNegative(max);
      return this;
    }

    public int getMaxChecks() {
      return maxChecks;
    }

    public PerBlock setMaxChecks(int max) {
      this.maxChecks = nonNegative(max);
      return this;
    }

    public int getMaxSymbols() {
      return maxSymbols;
    }

    public PerBlock setMaxSymbols(int max) {
      this.maxSymbols = nonNegative(max);
      return this;
    }

    public int getMaxPublicKeys() {
      return maxPublicKeys;
    }

    public PerBlock setMaxPublicKeys(int max) {
      this.maxPublicKeys = nonNegative(max);
      return this;
    }

    public int getMaxContextLength() {
      return maxContextLength;
    }

    public PerBlock setMaxContextLength(int max) {
      this.maxContextLength = nonNegative(max);
      return this;
    }

    public int getMaxQueriesPerCheck() {
      return maxQueriesPerCheck;
    }

    public PerBlock setMaxQueriesPerCheck(int max) {
      this.maxQueriesPerCheck = nonNegative(max);
      return this;
    }

    public int getMaxPredicatesPerBody() {
      return maxPredicatesPerBody;
    }

    public PerBlock setMaxPredicatesPerBody(int max) {
      this.maxPredicatesPerBody = nonNegative(max);
      return this;
    }

    public int getMaxExpressionsPerBody() {
      return maxExpressionsPerBody;
    }

    public PerBlock setMaxExpressionsPerBody(int max) {
      this.maxExpressionsPerBody = nonNegative(max);
      return this;
    }

    public int getMaxOpsPerExpression() {
      return maxOpsPerExpression;
    }

    public PerBlock setMaxOpsPerExpression(int max) {
      this.maxOpsPerExpression = nonNegative(max);
      return this;
    }

    public int getMaxTermsPerPredicate() {
      return maxTermsPerPredicate;
    }

    public PerBlock setMaxTermsPerPredicate(int max) {
      this.maxTermsPerPredicate = nonNegative(max);
      return this;
    }

    public int getMaxNameLength() {
      return maxNameLength;
    }

    public PerBlock setMaxNameLength(int max) {
      this.maxNameLength = nonNegative(max);
      return this;
    }

    public int getMaxBytesLength() {
      return maxBytesLength;
    }

    public PerBlock setMaxBytesLength(int max) {
      this.maxBytesLength = nonNegative(max);
      return this;
    }

    public int getMaxStringLength() {
      return maxStringLength;
    }

    public PerBlock setMaxStringLength(int max) {
      this.maxStringLength = nonNegative(max);
      return this;
    }

    public int getMaxSetLength() {
      return maxSetLength;
    }

    public PerBlock setMaxSetLength(int max) {
      this.maxSetLength = nonNegative(max);
      return this;
    }

    public int getMaxArrayLength() {
      return maxArrayLength;
    }

    public PerBlock setMaxArrayLength(int max) {
      this.maxArrayLength = nonNegative(max);
      return this;
    }

    public int getMaxMapLength() {
      return maxMapLength;
    }

    public PerBlock setMaxMapLength(int max) {
      this.maxMapLength = nonNegative(max);
      return this;
    }

    public Set<Op.BinaryOp> getAllowedBinaryOps() {
      return allowedBinaryOps;
    }

    public PerBlock setAllowedBinaryOps(Set<Op.BinaryOp> ops) {
      this.allowedBinaryOps = copy(ops);
      return this;
    }

    public Set<Op.UnaryOp> getAllowedUnaryOps() {
      return allowedUnaryOps;
    }

    public PerBlock setAllowedUnaryOps(Set<Op.UnaryOp> ops) {
      this.allowedUnaryOps = copy(ops);
      return this;
    }

    public Set<String> getAllowedUnaryExternalFunctions() {
      return allowedUnaryExternalFunctions;
    }

    public PerBlock setAllowedUnaryExternalFunctions(Set<String> names) {
      this.allowedUnaryExternalFunctions = copy(names);
      return this;
    }

    public Set<String> getAllowedBinaryExternalFunctions() {
      return allowedBinaryExternalFunctions;
    }

    public PerBlock setAllowedBinaryExternalFunctions(Set<String> names) {
      this.allowedBinaryExternalFunctions = copy(names);
      return this;
    }

    public Set<Term.TermType> getAllowedTermTypes() {
      return allowedTermTypes;
    }

    public PerBlock setAllowedTermTypes(Set<Term.TermType> types) {
      this.allowedTermTypes = copy(types);
      return this;
    }

    public Set<Term.MapKeyType> getAllowedMapKeyTypes() {
      return allowedMapKeyTypes;
    }

    public PerBlock setAllowedMapKeyTypes(Set<Term.MapKeyType> types) {
      this.allowedMapKeyTypes = copy(types);
      return this;
    }

    public Set<TrustedScopeKind> getAllowedTrustingScopes() {
      return allowedTrustingScopes;
    }

    public PerBlock setAllowedTrustingScopes(Set<TrustedScopeKind> scopes) {
      this.allowedTrustingScopes = copy(scopes);
      return this;
    }

    public Set<Check.Kind> getAllowedCheckKinds() {
      return allowedCheckKinds;
    }

    public PerBlock setAllowedCheckKinds(Set<Check.Kind> kinds) {
      this.allowedCheckKinds = copy(kinds);
      return this;
    }

    private Object[] state() {
      return new Object[] {
        allowClosures,
        maxBlockSize,
        maxFacts,
        maxRules,
        maxChecks,
        maxSymbols,
        maxPublicKeys,
        maxContextLength,
        maxQueriesPerCheck,
        maxPredicatesPerBody,
        maxExpressionsPerBody,
        maxOpsPerExpression,
        maxTermsPerPredicate,
        maxNameLength,
        maxBytesLength,
        maxStringLength,
        maxSetLength,
        maxArrayLength,
        maxMapLength,
        allowedBinaryOps,
        allowedUnaryOps,
        allowedUnaryExternalFunctions,
        allowedBinaryExternalFunctions,
        allowedTermTypes,
        allowedMapKeyTypes,
        allowedTrustingScopes,
        allowedCheckKinds
      };
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      return Arrays.equals(state(), ((PerBlock) o).state());
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(state());
    }
  }
}
