package org.biscuitsec.biscuit.error;

import org.biscuitsec.biscuit.datalog.expressions.Expression;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import io.vavr.control.Option;

import java.util.List;
import java.util.Objects;

public class Error extends Exception {
    public Option<List<FailedCheck>> failedChecks() {
        return Option.none();
    }

    public JsonElement toJson() {
        return new JsonObject();
    }

    public static class InternalError extends Error {}

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
            public static class InvalidFormat extends Signature {
                public InvalidFormat() {}
                @Override
                public boolean equals(Object o) {
                    if (this == o) return true;
                    return o != null && getClass() == o.getClass();
                }

                @Override
                public JsonElement toJson() {
                    return Signature.jsonWrapper(new JsonPrimitive("InvalidFormat"));
                }
                @Override
                public String toString(){
                    return "Err(Format(Signature(InvalidFormat)))";
                }
            }
            public static class InvalidSignature extends Signature {
                final public String e;
                public InvalidSignature(String e) {
                    this.e = e;
                }
                @Override
                public boolean equals(Object o) {
                    if (this == o) return true;
                    return o != null && getClass() == o.getClass();
                }
                @Override
                public JsonElement toJson() {
                    JsonObject jo = new JsonObject();
                    jo.addProperty("InvalidSignature", this.e);
                    return Signature.jsonWrapper(jo);
                }
                @Override
                public String toString(){
                    return "Err(Format(Signature(InvalidFormat(\""+this.e+"\"))))";
                }
            }
        }

        public static class SealedSignature extends FormatError {
            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                return o != null && getClass() == o.getClass();
            }
            @Override
            public JsonElement toJson() {
                return FormatError.jsonWrapper(new JsonPrimitive("SealedSignature"));
            }
            @Override
            public String toString(){
                return "Err(Format(SealedSignature))";
            }
        }
        public static class EmptyKeys extends FormatError {
            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                return o != null && getClass() == o.getClass();
            }
            @Override
            public JsonElement toJson() {
                return FormatError.jsonWrapper(new JsonPrimitive("EmptyKeys"));
            }
            @Override
            public String toString(){
                return "Err(Format(EmptyKeys))";
            }
        }
        public static class UnknownPublicKey extends FormatError {
            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                return o != null && getClass() == o.getClass();
            }
            @Override
            public JsonElement toJson() {
                return FormatError.jsonWrapper(new JsonPrimitive("UnknownPublicKey"));
            }
            @Override
            public String toString(){
                return "Err(Format(UnknownPublicKey))";
            }
        }
        public static class DeserializationError extends FormatError {
            final public String e;

            public DeserializationError(String e) {
                this.e = e;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                DeserializationError other = (DeserializationError) o;
                return e.equals(other.e);
            }

            @Override
            public int hashCode() {
                return Objects.hash(e);
            }

            @Override
            public String toString(){
                return "Err(Format(DeserializationError(\""+this.e+"\"))";
            }

            @Override
            public JsonElement toJson() {
                JsonObject jo = new JsonObject();
                jo.addProperty("DeserializationError", this.e);
                return FormatError.jsonWrapper(jo);
            }

        }

        public static class SerializationError extends FormatError {
            final public String e;

            public SerializationError(String e) {
                this.e = e;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                SerializationError other = (SerializationError) o;
                return e.equals(other.e);
            }

            @Override
            public int hashCode() {
                return Objects.hash(e);
            }

            @Override
            public String toString(){
                return "Err(Format(SerializationError(\""+this.e+"\"))";
            }

            @Override
            public JsonElement toJson() {
                JsonObject jo = new JsonObject();
                jo.addProperty("SerializationError", this.e);
                return FormatError.jsonWrapper(jo);
            }
        }
        public static class BlockDeserializationError extends FormatError {
            final public String e;

            public BlockDeserializationError(String e) {
                this.e = e;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                BlockDeserializationError other = (BlockDeserializationError) o;
                return e.equals(other.e);
            }

            @Override
            public int hashCode() {
                return Objects.hash(e);
            }

            @Override
            public String toString() {
                return "Err(FormatError.BlockDeserializationError{ error: "+  e + " }";
            }

            @Override
            public JsonElement toJson() {
                JsonObject jo = new JsonObject();
                jo.addProperty("BlockDeserializationError", this.e);
                return FormatError.jsonWrapper(jo);
            }
        }
        public static class BlockSerializationError extends FormatError {
            final public String e;

            public BlockSerializationError(String e) {
                this.e = e;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                BlockSerializationError other = (BlockSerializationError) o;
                return e.equals(other.e);
            }

            @Override
            public int hashCode() {
                return Objects.hash(e);
            }

            @Override
            public String toString() {
                return "Err(FormatError.BlockSerializationError{ error: "+  e + " }";
            }

            @Override
            public JsonElement toJson() {
                JsonObject jo = new JsonObject();
                jo.addProperty("BlockSerializationError", this.e);
                return FormatError.jsonWrapper(jo);
            }
        }

        public static class Version extends FormatError {
            final public int minimum;
            final public int maximum;
            final public int actual;

            public Version(int minimum, int maximum, int actual) {
                this.minimum = minimum;
                this.maximum = maximum;
                this.actual = actual;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;

                Version version = (Version) o;

                if (minimum != version.minimum) return false;
                if (maximum != version.maximum) return false;
                return actual == version.actual;
            }

            @Override
            public int hashCode() {
                return super.hashCode();
            }

            @Override
            public String toString() {
                return "Version{" +
                        "minimum=" + minimum +
                        ", maximum=" + maximum +
                        ", actual=" + actual +
                        '}';
            }
            @Override
            public JsonElement toJson() {
                JsonObject child = new JsonObject();
                child.addProperty("minimum",this.minimum);
                child.addProperty("maximum",this.maximum);
                child.addProperty("actual", this.actual);
                JsonObject jo = new JsonObject();
                jo.add("Version", child);
                return FormatError.jsonWrapper(jo);
            }
        }

        public static class InvalidSignatureSize extends FormatError {
            final public int size;

            public InvalidSignatureSize(int size) {
                this.size = size;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;

                InvalidSignatureSize iss = (InvalidSignatureSize) o;

                return size == iss.size;
            }

            @Override
            public int hashCode() {
                return Objects.hash(size);
            }

            @Override
            public String toString() {
                return "InvalidSignatureSize{" +
                        "size=" + size +
                        '}';
            }
            @Override
            public JsonElement toJson() {
                JsonObject jo = new JsonObject();
                jo.add("InvalidSignatureSize", new JsonPrimitive(size));
                return FormatError.jsonWrapper(jo);
            }
        }
    }
    public static class InvalidAuthorityIndex extends Error {
        final public long index;

        public InvalidAuthorityIndex(long index) {
            this.index = index;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            InvalidAuthorityIndex other = (InvalidAuthorityIndex) o;
            return index == other.index;
        }

        @Override
        public int hashCode() {
            return Objects.hash(index);
        }

        @Override
        public String toString() {
            return "Err(InvalidAuthorityIndex{ index: "+ index + " }";
        }

        @Override
        public JsonElement toJson() {
            JsonObject child = new JsonObject();
            child.addProperty("index",this.index);
            JsonObject jo = new JsonObject();
            jo.add("InvalidAuthorityIndex", child);
            return jo;
        }
    }
    public static class InvalidBlockIndex extends Error {
        final public long expected;
        final public long found;

        public InvalidBlockIndex(long expected, long found) {
            this.expected = expected;
            this.found = found;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
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
            child.addProperty("expected",this.expected);
            child.addProperty("fount", this.found);
            JsonObject jo = new JsonObject();
            jo.add("InvalidBlockIndex", child);
            return jo;
        }
    }
    public static class SymbolTableOverlap extends Error {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }

        @Override
        public JsonElement toJson(){
            return new JsonPrimitive("SymbolTableOverlap");
        }
    }
    public static class MissingSymbols extends Error {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }
        @Override
        public JsonElement toJson(){
            return new JsonPrimitive("MissingSymbols");
        }
    }
    public static class Sealed extends Error {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }
        @Override
        public JsonElement toJson(){
            return new JsonPrimitive("Sealed");
        }
    }
    public static class FailedLogic extends Error {
        final public LogicError error;

        public FailedLogic(LogicError error) {
            this.error = error;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FailedLogic other = (FailedLogic) o;
            return error.equals(other.error);
        }

        @Override
        public int hashCode() {
            return Objects.hash(error);
        }

        @Override
        public String toString() {
            return "Err(FailedLogic("+ error +"))";
        }

        @Override
        public Option<List<FailedCheck>> failedChecks() {
            return this.error.failedChecks();
        }

        @Override
        public JsonElement toJson(){
            JsonObject jo = new JsonObject();
            jo.add("FailedLogic", this.error.toJson());
            return jo;
        }

    }

    public static class Language extends Error {
        final public FailedCheck.LanguageError langError;
        public Language(FailedCheck.LanguageError langError){
            this.langError = langError;
        }
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }

        @Override
        public JsonElement toJson(){
            JsonObject jo = new JsonObject();
            jo.add("Language", langError.toJson());
            return jo;
        }
    }

    public static class TooManyFacts extends Error {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }
        @Override
        public JsonElement toJson(){
            return new JsonPrimitive("TooManyFacts");
        }
    }

    public static class TooManyIterations extends Error {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }
        @Override
        public JsonElement toJson(){
            return new JsonPrimitive("TooManyIterations");
        }
    }

    public static class Timeout extends Error {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }
        @Override
        public JsonElement toJson(){
            return new JsonPrimitive("Timeout");
        }
    }

    public static class Execution extends Error {
        public enum Kind {
            Execution,
            Overflow

        }
        Expression e;
        String message;

        Kind kind;

        public Execution(Expression ex, String msg) {
            e = ex;
            message = msg;
            kind = Kind.Execution;
        }

        public Execution( String msg) {
            e = null;
            message = msg;
            kind = Kind.Execution;
        }

        public Execution(Kind kind, String msg) {
            e = null;
            this.kind = kind;
            message = msg;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }
        @Override
        public JsonElement toJson(){
            JsonObject jo = new JsonObject();
            jo.add("Execution", new JsonPrimitive(this.kind.toString()));
            return jo;

        }

        @Override
        public String toString() {
            return "Execution error when evaluating expression '" + e +
                    "': " + message;
        }
    }

    public static class InvalidType extends Error {
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return o != null && getClass() == o.getClass();
        }
        @Override
        public JsonElement toJson(){
            return new JsonPrimitive("InvalidType");
        }
    }

    public static class Parser extends Error {
        final public org.biscuitsec.biscuit.token.builder.parser.Error error;

        public Parser(org.biscuitsec.biscuit.token.builder.parser.Error error) {
            this.error = error;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Parser parser = (Parser) o;

            return error.equals(parser.error);
        }

        @Override
        public int hashCode() {
            return error.hashCode();
        }

        @Override
        public String toString() {
            return "Parser{" +
                    "error=" + error +
                    '}';
        }

        @Override
        public JsonElement toJson(){
            JsonObject error = new JsonObject();
            error.add("error", this.error.toJson());
            return error;
        }
    }
}
