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
import io.vavr.control.Option;
import java.util.List;
import java.util.Objects;
import org.eclipse.biscuit.datalog.expressions.Expression;

public abstract class Error extends Exception {
  static final ObjectMapper objectMapper = new ObjectMapper();

  public Option<List<FailedCheck>> getFailedChecks() {
    return Option.none();
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
      return TextNode.valueOf("InternalError");
    }
  }

  public abstract static class FormatError extends Error {

    private static JsonNode jsonWrapper(JsonNode e) {
      return objectMapper.createObjectNode().set("Format", e);
    }

    public abstract static class Signature extends FormatError {
      private static JsonNode jsonWrapper(JsonNode e) {
        return FormatError.jsonWrapper(objectMapper.createObjectNode().set("Signature", e));
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
          return Signature.jsonWrapper(TextNode.valueOf("InvalidFormat"));
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
              objectMapper.createObjectNode().put("InvalidSignature", this.err));
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
        return Signature.jsonWrapper(TextNode.valueOf("SealedSignature"));
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
        return Signature.jsonWrapper(TextNode.valueOf("EmptyKeys"));
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
        return Signature.jsonWrapper(TextNode.valueOf("UnknownPublicKey"));
      }

      @Override
      public String toString() {
        return "Err(Format(UnknownPublicKey))";
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
            objectMapper.createObjectNode().put("DeserializationError", this.err));
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
            objectMapper.createObjectNode().put("SerializationError", this.err));
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
            objectMapper.createObjectNode().put("BlockDeserializationError", this.err));
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
            objectMapper.createObjectNode().put("BlockSerializationError", this.err));
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
        return FormatError.jsonWrapper(objectMapper.createObjectNode().set("Version", child));
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
            objectMapper.createObjectNode().set("InvalidSignatureSize", IntNode.valueOf(size)));
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
            objectMapper.createObjectNode().set("InvalidKeySize", IntNode.valueOf(size)));
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
            objectMapper.createObjectNode().set("InvalidKey", TextNode.valueOf(this.err)));
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
          objectMapper.createObjectNode().set("InvalidAuthorityIndex", child));
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
          objectMapper.createObjectNode().set("InvalidBlockIndex", child));
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
      return TextNode.valueOf("SymbolTableOverlap");
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
      return TextNode.valueOf("MissingSymbols");
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
      return TextNode.valueOf("Sealed");
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
    public Option<List<FailedCheck>> getFailedChecks() {
      return this.error.getFailedChecks();
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().set("FailedLogic", error.toJson());
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
      return objectMapper.createObjectNode().set("Language", langError.toJson());
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
      return TextNode.valueOf("TooManyFacts");
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
      return TextNode.valueOf("TooManyIterations");
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
      return TextNode.valueOf("Timeout");
    }
  }

  public static final class Execution extends Error {
    public enum Kind {
      Execution,
      Overflow
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

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("Execution", kind.toString());
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
      return TextNode.valueOf("InvalidType");
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
