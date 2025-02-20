package org.biscuitsec.biscuit.error;

import com.google.gson.*;

import java.util.List;
import java.util.Objects;

public class FailedCheck {

    public JsonElement toJson(){
        return new JsonObject();
    }

    public static class FailedBlock extends FailedCheck {
        final public long block_id;
        final public long check_id;
        final public String rule;

        public FailedBlock(long block_id, long check_id, String rule) {
            this.block_id = block_id;
            this.check_id = check_id;
            this.rule = rule;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FailedBlock b = (FailedBlock) o;
            return block_id == b.block_id && check_id == b.check_id && rule.equals(b.rule);
        }

        @Override
        public int hashCode() {
            return Objects.hash(block_id, check_id, rule);
        }

        @Override
        public String toString() {
            return "Block(FailedBlockCheck " + new Gson().toJson(toJson())+")";
        }

        @Override
        public JsonElement toJson() {
            JsonObject jo = new JsonObject();
            jo.addProperty("block_id", block_id);
            jo.addProperty("check_id", check_id);
            jo.addProperty("rule", rule);
            JsonObject block = new JsonObject();
            block.add("Block", jo);
            return block;
        }
    }

    public static class FailedAuthorizer extends FailedCheck {
        final public long check_id;
        final public String rule;

        public FailedAuthorizer(long check_id, String rule) {
            this.check_id = check_id;
            this.rule = rule;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FailedAuthorizer b = (FailedAuthorizer) o;
            return check_id == b.check_id && rule.equals(b.rule);
        }

        @Override
        public int hashCode() {
            return Objects.hash(check_id, rule);
        }

        @Override
        public String toString() {
            return "FailedCaveat.FailedAuthorizer { check_id: "+check_id+
                    ", rule: "+rule+" }";
        }

        @Override
        public JsonElement toJson() {
            JsonObject jo = new JsonObject();
            jo.addProperty("check_id", check_id);
            jo.addProperty("rule", rule);
            JsonObject authorizer = new JsonObject();
            authorizer.add("Authorizer", jo);
            return authorizer;
        }
    }

    public static class ParseErrors extends FailedCheck {

    }

    public static class LanguageError extends FailedCheck {
        public static class ParseError extends LanguageError {

            @Override
            public JsonElement toJson() {
                return new JsonPrimitive("ParseError");
            }
        }
        public static class Builder extends LanguageError {
            List<String> invalid_variables;
            public Builder(List<String> invalid_variables) {
                this.invalid_variables = invalid_variables;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                Builder b = (Builder) o;
                return invalid_variables == b.invalid_variables && invalid_variables.equals(b.invalid_variables);
            }

            @Override
            public int hashCode() {
                return Objects.hash(invalid_variables);
            }

            @Override
            public String toString() {
                return "InvalidVariables { message: "+invalid_variables+" }";
            }

            @Override
            public JsonElement toJson() {
                JsonObject authorizer = new JsonObject();
                JsonArray ja = new JsonArray();
                for(String s : invalid_variables){
                    ja.add(s);
                }
                authorizer.add("InvalidVariables", ja);
                return authorizer;
            }
        }

        public static class UnknownVariable extends LanguageError {
            String message;
            public UnknownVariable(String message) {
                this.message = message;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UnknownVariable b = (UnknownVariable) o;
                return this.message == b.message && message.equals(b.message);
            }

            @Override
            public int hashCode() {
                return Objects.hash(message);
            }

            @Override
            public String toString() {
                return "LanguageError.UnknownVariable { message: "+message+ " }";
            }

            @Override
            public JsonElement toJson() {
                JsonObject authorizer = new JsonObject();
                authorizer.add("UnknownVariable", new JsonPrimitive(message));
                return authorizer;
            }
        }
    }
}