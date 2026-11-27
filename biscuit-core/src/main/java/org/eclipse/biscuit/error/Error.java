/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.error;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.eclipse.biscuit.datalog.expressions.Expression;

public abstract class Error extends Exception {
  static final ObjectMapper objectMapper = new ObjectMapper();

  public Optional<List<FailedCheck>> getFailedChecks() {
    return Optional.empty();
  }

  /**
   * Serialize error to JSON
   *
   * @return json object
   */
  public abstract JsonNode toJson();

  public static final class InternalError extends Error {
    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "internal_error");
    }
  }

  public abstract static class FormatError extends Error {

    private static JsonNode jsonWrapper(JsonNode e) {
      return objectMapper.createObjectNode().put("type", "format").set("value", e);
    }

    public abstract static class Signature extends FormatError {
      private static JsonNode jsonWrapper(JsonNode e) {
        return FormatError.jsonWrapper(
            objectMapper.createObjectNode().put("type", "signature").set("value", e));
      }

      public static final class InvalidFormat extends Signature {
        public InvalidFormat() {}

        @Override
        public boolean equals(Object o) {
          if (this == o) {
            return true;
          }
          return o != null && getClass() == o.getClass();
        }

        @Override
        public JsonNode toJson() {
          return Signature.jsonWrapper(
              objectMapper.createObjectNode().put("type", "invalid_format"));
        }

        @Override
        public String toString() {
          return "Err(Format(Signature(InvalidFormat)))";
        }
      }

      public static final class InvalidSignature extends Signature {
        private final String err;

        public InvalidSignature(String e) {
          this.err = e;
        }

        @Override
        public boolean equals(Object o) {
          if (this == o) {
            return true;
          }
          return o != null && getClass() == o.getClass();
        }

        @Override
        public JsonNode toJson() {
          return Signature.jsonWrapper(
              objectMapper
                  .createObjectNode()
                  .put("type", "invalid_signature")
                  .put("value", this.err));
        }

        @Override
        public String toString() {
          return "Err(Format(Signature(InvalidFormat(\"" + this.err + "\"))))";
        }
      }
    }

    public static final class SealedSignature extends FormatError {
      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        return o != null && getClass() == o.getClass();
      }

      @Override
      public JsonNode toJson() {
        return Signature.jsonWrapper(
            objectMapper.createObjectNode().put("type", "sealed_signature"));
      }

      @Override
      public String toString() {
        return "Err(Format(SealedSignature))";
      }
    }

    public static final class EmptyKeys extends FormatError {
      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        return o != null && getClass() == o.getClass();
      }

      @Override
      public JsonNode toJson() {
        return Signature.jsonWrapper(objectMapper.createObjectNode().put("type", "empty_keys"));
      }

      @Override
      public String toString() {
        return "Err(Format(EmptyKeys))";
      }
    }

    public static final class UnknownPublicKey extends FormatError {
      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        return o != null && getClass() == o.getClass();
      }

      @Override
      public JsonNode toJson() {
        return Signature.jsonWrapper(
            objectMapper.createObjectNode().put("type", "unknown_public_key"));
      }

      @Override
      public String toString() {
        return "Err(Format(UnknownPublicKey))";
      }
    }

    public static final class UnknownSymbol extends FormatError {
      private final long symbol;

      public UnknownSymbol(long symbol) {
        this.symbol = symbol;
      }

      public long getSymbol() {
        return symbol;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        return symbol == ((UnknownSymbol) o).symbol;
      }

      @Override
      public int hashCode() {
        return Objects.hash(symbol);
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper.createObjectNode().put("type", "unknown_symbol").put("value", symbol));
      }

      @Override
      public String toString() {
        return "Err(Format(UnknownSymbol(" + symbol + ")))";
      }
    }

    public static final class DeserializationError extends FormatError {
      private final String err;

      public DeserializationError(String e) {
        this.err = e;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        DeserializationError other = (DeserializationError) o;
        return err.equals(other.err);
      }

      @Override
      public int hashCode() {
        return Objects.hash(err);
      }

      @Override
      public String toString() {
        return "Err(Format(DeserializationError(\"" + this.err + "\"))";
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "deserialization_error")
                .put("value", this.err));
      }
    }

    /** The token contains a feature which is not permitted by the DeserializationLimit it was checked with */
    public static final class DeserializationLimitError extends FormatError {
      /** The way in which a token violated the DeserializationLimit */
      public enum Reason {
        TOKEN_TOO_LARGE("Biscuit is too large"),
        BLOCK_TOO_LARGE("Biscuit Datalog block is too large"),
        TOO_MANY_BLOCKS("Biscuit contains too many blocks"),
        TOO_MANY_FACTS("Biscuit block contains too many facts"),
        TOO_MANY_RULES("Biscuit block contains too many rules"),
        TOO_MANY_CHECKS("Biscuit block contains too many checks"),
        TOO_MANY_SYMBOLS("Biscuit block contains too many symbols"),
        TOO_MANY_PUBLIC_KEYS("Biscuit block contains too many public keys"),
        TOO_MANY_QUERIES("Biscuit check contains too many queries"),
        TOO_MANY_PREDICATES("Biscuit rule or query body contains too many predicates"),
        TOO_MANY_EXPRESSIONS("Biscuit rule or query body contains too many expressions"),
        TOO_MANY_OPS("Biscuit expression contains too many operations"),
        TOO_MANY_TERMS("Biscuit fact or predicate contains too many terms"),
        NAME_TOO_LONG("Biscuit contains a name which is too long"),
        STRING_TOO_LONG("Biscuit contains a string which is too long"),
        BYTES_TOO_LONG("Biscuit contains a bytes value which is too long"),
        SET_TOO_LONG("Biscuit contains a set which is too long"),
        ARRAY_TOO_LONG("Biscuit contains an array which is too long"),
        MAP_TOO_LONG("Biscuit contains a map which is too long"),
        CLOSURES_NOT_ALLOWED("Biscuit contains closures, which are not allowed"),
        SIGNATURE_VERSION_TOO_LOW("Biscuit block uses a signature version which is too low"),
        INTERNAL_SIGNING_ALGORITHM_NOT_ALLOWED(
            "Biscuit block is signed with an algorithm which is not allowed"),
        EXTERNAL_SIGNING_ALGORITHM_NOT_ALLOWED(
            "Biscuit block has a third party signature with an algorithm which is not allowed"),
        BINARY_OPERATION_NOT_ALLOWED("Biscuit contains a binary operation which is not allowed"),
        UNARY_OPERATION_NOT_ALLOWED("Biscuit contains a unary operation which is not allowed"),
        EXTERNAL_FUNCTION_NOT_ALLOWED("Biscuit calls a foreign function which is not allowed"),
        TERM_TYPE_NOT_ALLOWED("Biscuit contains a term of a type which is not allowed"),
        MAP_KEY_TYPE_NOT_ALLOWED("Biscuit contains a map key of a type which is not allowed"),
        TRUSTED_SCOPE_NOT_ALLOWED("Biscuit trusts a scope which is not allowed"),
        CONTEXT_TOO_LONG("Biscuit block contains a context which is too long"),
        CHECK_KIND_NOT_ALLOWED("Biscuit contains a kind of check which is not allowed"),
        SEALED_TOKENS_NOT_ALLOWED("Biscuit is sealed, which is not allowed"),
        UNSEALED_TOKENS_NOT_ALLOWED("Biscuit is not sealed, which is not allowed"),
        ATTENUATIONS_WITH_EXTERNAL_SIGNATURES_NOT_ALLOWED(
            "Biscuit contains attenuations with external signatures, which are not allowed"),
        ATTENUATIONS_WITHOUT_EXTERNAL_SIGNATURES_NOT_ALLOWED(
            "Biscuit contains attenuations without external signatures, which are not allowed");

        private final String description;

        Reason(String description) {
          this.description = description;
        }

        public String description() {
          return description;
        }
      }

      private final Reason reason;

      public DeserializationLimitError(Reason reason) {
        super();
        this.reason = reason;
      }

      public Reason getReason() {
        return reason;
      }

      @Override
      public String getMessage() {
        return reason.description();
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        return reason == ((DeserializationLimitError) o).reason;
      }

      @Override
      public int hashCode() {
        return Objects.hash(reason);
      }

      @Override
      public String toString() {
        return "Err(Format(DeserializationLimitError(" + this.reason + ")))";
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "deserialization_limit_error")
                .put("value", this.reason.name()));
      }
    }

    public static final class SerializationError extends FormatError {
      private final String err;

      public SerializationError(String e) {
        this.err = e;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        SerializationError other = (SerializationError) o;
        return err.equals(other.err);
      }

      @Override
      public int hashCode() {
        return Objects.hash(err);
      }

      @Override
      public String toString() {
        return "Err(Format(SerializationError(\"" + this.err + "\"))";
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "serialization_error")
                .put("value", this.err));
      }
    }

    public static final class BlockDeserializationError extends FormatError {
      private final String err;

      public BlockDeserializationError(String e) {
        this.err = e;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        BlockDeserializationError other = (BlockDeserializationError) o;
        return err.equals(other.err);
      }

      @Override
      public int hashCode() {
        return Objects.hash(err);
      }

      @Override
      public String toString() {
        return "Err(FormatError.BlockDeserializationError{ error: " + err + " }";
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "block_deserialization_error")
                .put("value", this.err));
      }
    }

    public static final class BlockSignatureDeserializationError extends FormatError {
      private final String err;

      public BlockSignatureDeserializationError(byte[] signature) {
        this.err =
            "block signature deserialization error: "
                + IntStream.range(0, signature.length)
                    .mapToObj(i -> String.valueOf(signature[i] & 0xff))
                    .collect(Collectors.joining(", ", "[", "]"));
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        BlockSignatureDeserializationError other = (BlockSignatureDeserializationError) o;
        return err.equals(other.err);
      }

      @Override
      public int hashCode() {
        return Objects.hash(err);
      }

      @Override
      public String toString() {
        return "Err(FormatError.BlockSignatureDeserializationError{ error: " + err + " }";
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "block_signature_deserialization_error")
                .put("value", this.err));
      }
    }

    public static final class BlockSerializationError extends FormatError {
      private final String err;

      public BlockSerializationError(String e) {
        this.err = e;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        BlockSerializationError other = (BlockSerializationError) o;
        return err.equals(other.err);
      }

      @Override
      public int hashCode() {
        return Objects.hash(err);
      }

      @Override
      public String toString() {
        return "Err(FormatError.BlockSerializationError{ error: " + err + " }";
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "block_serialization_error")
                .put("value", this.err));
      }
    }

    public static final class Version extends FormatError {
      private final int minimum;
      private final int maximum;
      private final int actual;

      public Version(int minimum, int maximum, int actual) {
        this.minimum = minimum;
        this.maximum = maximum;
        this.actual = actual;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }

        Version version = (Version) o;

        if (minimum != version.minimum) {
          return false;
        }
        if (maximum != version.maximum) {
          return false;
        }
        return actual == version.actual;
      }

      @Override
      public int hashCode() {
        return super.hashCode();
      }

      @Override
      public String toString() {
        return "Version{"
            + "minimum="
            + minimum
            + ", maximum="
            + maximum
            + ", actual="
            + actual
            + '}';
      }

      @Override
      public JsonNode toJson() {
        ObjectNode child =
            objectMapper
                .createObjectNode()
                .put("minimum", this.minimum)
                .put("maximum", this.maximum)
                .put("actual", this.actual);
        return FormatError.jsonWrapper(
            objectMapper.createObjectNode().put("type", "version").set("value", child));
      }
    }

    public static final class InvalidSignatureSize extends FormatError {
      private final int size;

      public InvalidSignatureSize(int size) {
        this.size = size;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }

        InvalidSignatureSize iss = (InvalidSignatureSize) o;

        return size == iss.size;
      }

      @Override
      public int hashCode() {
        return Objects.hash(size);
      }

      @Override
      public String toString() {
        return "InvalidSignatureSize{" + "size=" + size + '}';
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "invalid_signature_size")
                .set("value", IntNode.valueOf(size)));
      }
    }

    public static final class InvalidKeySize extends FormatError {
      private final int size;

      public InvalidKeySize(int size) {
        this.size = size;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }

        InvalidKeySize iss = (InvalidKeySize) o;

        return size == iss.size;
      }

      @Override
      public int hashCode() {
        return Objects.hash(size);
      }

      @Override
      public String toString() {
        return "InvalidKeySize{" + "size=" + size + '}';
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "invalid_key_size")
                .set("value", IntNode.valueOf(size)));
      }
    }

    public static final class InvalidKey extends FormatError {
      private final String err;

      public InvalidKey(String e) {
        this.err = e;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        InvalidKey other = (InvalidKey) o;
        return err.equals(other.err);
      }

      @Override
      public int hashCode() {
        return Objects.hash(err);
      }

      @Override
      public String toString() {
        return "Err(Format(InvalidKey(\"" + this.err + "\"))";
      }

      @Override
      public JsonNode toJson() {
        return FormatError.jsonWrapper(
            objectMapper
                .createObjectNode()
                .put("type", "invalid_key")
                .set("value", TextNode.valueOf(this.err)));
      }
    }
  }

  public static final class InvalidAuthorityIndex extends Error {
    public final long index;

    public InvalidAuthorityIndex(long index) {
      this.index = index;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      InvalidAuthorityIndex other = (InvalidAuthorityIndex) o;
      return index == other.index;
    }

    @Override
    public int hashCode() {
      return Objects.hash(index);
    }

    @Override
    public String toString() {
      return "Err(InvalidAuthorityIndex{ index: " + index + " }";
    }

    @Override
    public JsonNode toJson() {
      ObjectNode child = objectMapper.createObjectNode().put("index", index);
      return FormatError.jsonWrapper(
          objectMapper
              .createObjectNode()
              .put("type", "invalid_authority_index")
              .set("value", child));
    }
  }

  public static final class InvalidBlockIndex extends Error {
    public final long expected;
    public final long found;

    public InvalidBlockIndex(long expected, long found) {
      this.expected = expected;
      this.found = found;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      InvalidBlockIndex other = (InvalidBlockIndex) o;
      return expected == other.expected && found == other.found;
    }

    @Override
    public int hashCode() {
      return Objects.hash(expected, found);
    }

    @Override
    public String toString() {
      return "Err(InvalidBlockIndex{ expected: " + expected + ", found: " + found + " }";
    }

    @Override
    public JsonNode toJson() {
      ObjectNode child =
          objectMapper.createObjectNode().put("expected", expected).put("found", found);
      return FormatError.jsonWrapper(
          objectMapper.createObjectNode().put("type", "invalid_block_index").set("value", child));
    }
  }

  public static final class SymbolTableOverlap extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "symbol_table_overlap");
    }
  }

  public static final class MissingSymbols extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "missing_symbols");
    }
  }

  public static final class Sealed extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "sealed");
    }
  }

  public static final class FailedLogic extends Error {
    public final LogicError error;

    public FailedLogic(LogicError error) {
      this.error = error;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      FailedLogic other = (FailedLogic) o;
      return error.equals(other.error);
    }

    @Override
    public int hashCode() {
      return Objects.hash(error);
    }

    @Override
    public String toString() {
      return "Err(FailedLogic(" + error + "))";
    }

    @Override
    public Optional<List<FailedCheck>> getFailedChecks() {
      return this.error.getFailedChecks();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper
          .createObjectNode()
          .put("type", "failed_logic")
          .set("value", error.toJson());
    }
  }

  public static final class Language extends Error {
    public final FailedCheck.LanguageError langError;

    public Language(FailedCheck.LanguageError langError) {
      this.langError = langError;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper
          .createObjectNode()
          .put("type", "language")
          .set("value", langError.toJson());
    }
  }

  public static final class TooManySteps extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "too_many_steps");
    }
  }

  public static final class TooManyFacts extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "too_many_facts");
    }
  }

  public static final class TooManyIterations extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "too_many_iterations");
    }
  }

  public static final class Timeout extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "timeout");
    }
  }

  public static final class Execution extends Error {
    public enum Kind {
      Execution,
      Overflow,
      ShadowedVariable,
      InvalidType
    }

    Expression expr;
    String message;

    Kind kind;

    public Execution(Expression ex, String msg) {
      expr = ex;
      message = msg;
      kind = Kind.Execution;
    }

    public Execution(String msg) {
      expr = null;
      message = msg;
      kind = Kind.Execution;
    }

    public Execution(Kind kind, String msg) {
      expr = null;
      this.kind = kind;
      message = msg;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    private String kind2String(Kind k) {
      switch (k) {
        case Execution:
          return "execution";
        case Overflow:
          return "overflow";
        case InvalidType:
          return "invalid_type";
        case ShadowedVariable:
          return "shadowed_variable";
      }
      return "";
    }

    @Override
    public JsonNode toJson() {
      var kindObj = objectMapper.createObjectNode().put("type", kind2String(kind));
      return objectMapper.createObjectNode().put("type", "execution").set("value", kindObj);
    }

    @Override
    public String toString() {
      return "Execution error when evaluating expression '" + expr + "': " + message;
    }
  }

  public static final class InvalidType extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "invalid_type");
    }
  }

  public static final class Shadowing extends Error {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      return o != null && getClass() == o.getClass();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "shadowing");
    }
  }

  public static final class Parser extends Error {
    public final org.eclipse.biscuit.token.builder.parser.Error error;

    public Parser(org.eclipse.biscuit.token.builder.parser.Error error) {
      this.error = error;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      Parser parser = (Parser) o;

      return error.equals(parser.error);
    }

    @Override
    public int hashCode() {
      return error.hashCode();
    }

    @Override
    public String toString() {
      return "Parser{error=" + error + '}';
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().set("error", objectMapper.valueToTree(error));
    }
  }
}
