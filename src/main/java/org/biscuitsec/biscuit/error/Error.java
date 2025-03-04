package org.biscuitsec.biscuit.error;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import io.vavr.control.Option;
import java.util.List;
import java.util.Objects;
import org.biscuitsec.biscuit.datalog.expressions.Expression;

public class Error extends Exception {
  public Option<List<FailedCheck>> failedChecks() {
    return Option.none();
  }

  /**
   * Serialize error to JSON
   *
   * @return json object
   */
  public JsonElement toJson() {
    return new JsonObject();
  }

  public static final class InternalError extends Error {}

  public static class FormatError extends Error {

    private static JsonElement jsonWrapper(JsonElement e) {
      JsonObject root = new JsonObject();
      root.add("Format", e);
      return root;
    }

    public static class Signature extends FormatError {
      private static JsonElement jsonWrapper(JsonElement e) {
        JsonObject signature = new JsonObject();
        signature.add("Signature", e);
        return FormatError.jsonWrapper(signature);
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
        public JsonElement toJson() {
          return Signature.jsonWrapper(new JsonPrimitive("InvalidFormat"));
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
        public JsonElement toJson() {
          JsonObject jo = new JsonObject();
          jo.addProperty("InvalidSignature", this.err);
          return Signature.jsonWrapper(jo);
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
      public JsonElement toJson() {
        return FormatError.jsonWrapper(new JsonPrimitive("SealedSignature"));
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
      public JsonElement toJson() {
        return FormatError.jsonWrapper(new JsonPrimitive("EmptyKeys"));
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
      public JsonElement toJson() {
        return FormatError.jsonWrapper(new JsonPrimitive("UnknownPublicKey"));
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
      public JsonElement toJson() {
        JsonObject jo = new JsonObject();
        jo.addProperty("DeserializationError", this.err);
        return FormatError.jsonWrapper(jo);
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
      public JsonElement toJson() {
        JsonObject jo = new JsonObject();
        jo.addProperty("SerializationError", this.err);
        return FormatError.jsonWrapper(jo);
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
      public JsonElement toJson() {
        JsonObject jo = new JsonObject();
        jo.addProperty("BlockDeserializationError", this.err);
        return FormatError.jsonWrapper(jo);
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
      public JsonElement toJson() {
        JsonObject jo = new JsonObject();
        jo.addProperty("BlockSerializationError", this.err);
        return FormatError.jsonWrapper(jo);
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
      public JsonElement toJson() {
        JsonObject child = new JsonObject();
        child.addProperty("minimum", this.minimum);
        child.addProperty("maximum", this.maximum);
        child.addProperty("actual", this.actual);
        JsonObject jo = new JsonObject();
        jo.add("Version", child);
        return FormatError.jsonWrapper(jo);
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
      public JsonElement toJson() {
        JsonObject jo = new JsonObject();
        jo.add("InvalidSignatureSize", new JsonPrimitive(size));
        return FormatError.jsonWrapper(jo);
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
    public JsonElement toJson() {
      JsonObject child = new JsonObject();
      child.addProperty("index", this.index);
      JsonObject jo = new JsonObject();
      jo.add("InvalidAuthorityIndex", child);
      return jo;
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
    public JsonElement toJson() {
      JsonObject child = new JsonObject();
      child.addProperty("expected", this.expected);
      child.addProperty("fount", this.found);
      JsonObject jo = new JsonObject();
      jo.add("InvalidBlockIndex", child);
      return jo;
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
    public JsonElement toJson() {
      return new JsonPrimitive("SymbolTableOverlap");
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
    public JsonElement toJson() {
      return new JsonPrimitive("MissingSymbols");
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
    public JsonElement toJson() {
      return new JsonPrimitive("Sealed");
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
    public Option<List<FailedCheck>> failedChecks() {
      return this.error.failedChecks();
    }

    @Override
    public JsonElement toJson() {
      JsonObject jo = new JsonObject();
      jo.add("FailedLogic", this.error.toJson());
      return jo;
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
    public JsonElement toJson() {
      JsonObject jo = new JsonObject();
      jo.add("Language", langError.toJson());
      return jo;
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
    public JsonElement toJson() {
      return new JsonPrimitive("TooManyFacts");
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
    public JsonElement toJson() {
      return new JsonPrimitive("TooManyIterations");
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
    public JsonElement toJson() {
      return new JsonPrimitive("Timeout");
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
    public JsonElement toJson() {
      JsonObject jo = new JsonObject();
      jo.add("Execution", new JsonPrimitive(this.kind.toString()));
      return jo;
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
    public JsonElement toJson() {
      return new JsonPrimitive("InvalidType");
    }
  }

  public static final class Parser extends Error {
    public final org.biscuitsec.biscuit.token.builder.parser.Error error;

    public Parser(org.biscuitsec.biscuit.token.builder.parser.Error error) {
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
    public JsonElement toJson() {
      JsonObject error = new JsonObject();
      error.add("error", this.error.toJson());
      return error;
    }
  }
}
