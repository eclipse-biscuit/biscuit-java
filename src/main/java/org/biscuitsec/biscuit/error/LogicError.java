package org.biscuitsec.biscuit.error;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import io.vavr.control.Option;
import java.util.List;
import java.util.Objects;

public class LogicError {
  public Option<List<FailedCheck>> failedChecks() {
    return Option.none();
  }

  public JsonElement toJson() {
    return new JsonObject();
  }

  public static final class InvalidAuthorityFact extends LogicError {
    public final String e;

    public InvalidAuthorityFact(String e) {
      this.e = e;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      InvalidAuthorityFact other = (InvalidAuthorityFact) o;
      return e.equals(other.e);
    }

    @Override
    public int hashCode() {
      return Objects.hash(e);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidAuthorityFact{ error: " + e + " }";
    }

    @Override
    public JsonElement toJson() {
      return new JsonPrimitive("InvalidAuthorityFact");
    }
  }

  public static final class InvalidAmbientFact extends LogicError {
    public final String e;

    public InvalidAmbientFact(String e) {
      this.e = e;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      InvalidAmbientFact other = (InvalidAmbientFact) o;
      return e.equals(other.e);
    }

    @Override
    public int hashCode() {
      return Objects.hash(e);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidAmbientFact{ error: " + e + " }";
    }

    @Override
    public JsonElement toJson() {
      JsonObject child = new JsonObject();
      child.addProperty("error", this.e);
      JsonObject root = new JsonObject();
      root.add("InvalidAmbientFact", child);
      return root;
    }
  }

  public static final class InvalidBlockFact extends LogicError {
    public final long id;
    public final String e;

    public InvalidBlockFact(long id, String e) {
      this.id = id;
      this.e = e;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      InvalidBlockFact other = (InvalidBlockFact) o;
      return id == other.id && e.equals(other.e);
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, e);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidBlockFact{ id: " + id + ", error: " + e + " }";
    }

    @Override
    public JsonElement toJson() {
      JsonObject child = new JsonObject();
      child.addProperty("id", this.id);
      child.addProperty("error", this.e);
      JsonObject root = new JsonObject();
      root.add("InvalidBlockFact", child);
      return root;
    }
  }

  public static final class InvalidBlockRule extends LogicError {
    public final long id;
    public final String e;

    public InvalidBlockRule(long id, String e) {
      this.id = id;
      this.e = e;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      InvalidBlockRule other = (InvalidBlockRule) o;
      return id == other.id && e.equals(other.e);
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, e);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidBlockRule{ id: " + id + ", error: " + e + " }";
    }

    @Override
    public JsonElement toJson() {
      JsonArray child = new JsonArray();
      child.add(this.id);
      child.add(this.e);
      JsonObject root = new JsonObject();
      root.add("InvalidBlockRule", child);
      return root;
    }
  }

  public static final class Unauthorized extends LogicError {
    public final List<FailedCheck> errors;
    public final MatchedPolicy policy;

    public Unauthorized(MatchedPolicy policy, List<FailedCheck> errors) {
      this.errors = errors;
      this.policy = policy;
    }

    public Option<List<FailedCheck>> failedChecks() {
      return Option.some(errors);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      Unauthorized other = (Unauthorized) o;
      if (errors.size() != other.errors.size()) {
        return false;
      }
      for (int i = 0; i < errors.size(); i++) {
        if (!errors.get(i).equals(other.errors.get(i))) {
          return false;
        }
      }
      return true;
    }

    @Override
    public int hashCode() {
      return Objects.hash(errors);
    }

    @Override
    public String toString() {
      return "Unauthorized(policy = " + policy + " errors = " + errors + ")";
    }

    @Override
    public JsonElement toJson() {
      JsonObject jo = new JsonObject();
      JsonObject unauthorized = new JsonObject();
      unauthorized.add("policy", this.policy.toJson());
      JsonArray ja = new JsonArray();
      for (FailedCheck t : this.errors) {
        ja.add(t.toJson());
      }
      unauthorized.add("checks", ja);
      jo.add("Unauthorized", unauthorized);
      return jo;
    }
  }

  public static final class NoMatchingPolicy extends LogicError {
    public final List<FailedCheck> errors;

    public NoMatchingPolicy(List<FailedCheck> errors) {
      this.errors = errors;
    }

    @Override
    public int hashCode() {
      return Objects.hash(errors);
    }

    @Override
    public Option<List<FailedCheck>> failedChecks() {
      return Option.some(errors);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      Unauthorized other = (Unauthorized) o;
      if (errors.size() != other.errors.size()) {
        return false;
      }
      for (int i = 0; i < errors.size(); i++) {
        if (!errors.get(i).equals(other.errors.get(i))) {
          return false;
        }
      }
      return true;
    }

    @Override
    public String toString() {
      return "NoMatchingPolicy{ }";
    }

    @Override
    public JsonElement toJson() {
      JsonObject jo = new JsonObject();
      JsonArray ja = new JsonArray();
      for (FailedCheck t : this.errors) {
        ja.add(t.toJson());
      }
      jo.add("NoMatchingPolicy", ja);
      return jo;
    }
  }

  public static final class AuthorizerNotEmpty extends LogicError {

    public AuthorizerNotEmpty() {}

    @Override
    public int hashCode() {
      return super.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      return super.equals(obj);
    }

    @Override
    public String toString() {
      return "AuthorizerNotEmpty";
    }
  }

  public abstract static class MatchedPolicy {
    public abstract JsonElement toJson();

    public static final class Allow extends MatchedPolicy {
      public final long nb;

      public Allow(long nb) {
        this.nb = nb;
      }

      @Override
      public String toString() {
        return "Allow(" + this.nb + ")";
      }

      public JsonElement toJson() {
        JsonObject jo = new JsonObject();
        jo.addProperty("Allow", this.nb);
        return jo;
      }
    }

    public static final class Deny extends MatchedPolicy {
      public final long nb;

      public Deny(long nb) {
        this.nb = nb;
      }

      @Override
      public String toString() {
        return "Deny(" + this.nb + ")";
      }

      public JsonElement toJson() {
        JsonObject jo = new JsonObject();
        jo.addProperty("Deny", this.nb);
        return jo;
      }
    }
  }
}
