/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.error;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public abstract class LogicError {
  static final ObjectMapper objectMapper = new ObjectMapper();

  public Optional<List<FailedCheck>> getFailedChecks() {
    return Optional.empty();
  }

  public abstract JsonNode toJson();

  public static final class InvalidAuthorityFact extends LogicError {
    public final String err;

    public InvalidAuthorityFact(String e) {
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
      InvalidAuthorityFact other = (InvalidAuthorityFact) o;
      return err.equals(other.err);
    }

    @Override
    public int hashCode() {
      return Objects.hash(err);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidAuthorityFact{ error: " + err + " }";
    }

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "invalid_authority_fact");
    }
  }

  public static final class InvalidAmbientFact extends LogicError {
    public final String err;

    public InvalidAmbientFact(String e) {
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
      InvalidAmbientFact other = (InvalidAmbientFact) o;
      return err.equals(other.err);
    }

    @Override
    public int hashCode() {
      return Objects.hash(err);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidAmbientFact{ error: " + err + " }";
    }

    @Override
    public JsonNode toJson() {
      ObjectNode child =
          objectMapper.createObjectNode().put("type", "error").put("value", this.err);
      return objectMapper
          .createObjectNode()
          .put("type", "invalid_ambient_fact")
          .set("value", child);
    }
  }

  public static final class InvalidBlockFact extends LogicError {
    public final long id;
    public final String err;

    public InvalidBlockFact(long id, String e) {
      this.id = id;
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
      InvalidBlockFact other = (InvalidBlockFact) o;
      return id == other.id && err.equals(other.err);
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, err);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidBlockFact{ id: " + id + ", error: " + err + " }";
    }

    @Override
    public JsonNode toJson() {
      ObjectNode child = objectMapper.createObjectNode().put("id", id).put("error", err);
      return objectMapper.createObjectNode().put("type", "invalid_block_fact").set("value", child);
    }
  }

  public static final class InvalidBlockRule extends LogicError {
    public final long id;
    public final String err;

    public InvalidBlockRule(long id, String e) {
      this.id = id;
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
      InvalidBlockRule other = (InvalidBlockRule) o;
      return id == other.id && err.equals(other.err);
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, err);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidBlockRule{ id: " + id + ", error: " + err + " }";
    }

    @Override
    public JsonNode toJson() {
      ArrayNode child = objectMapper.createArrayNode();
      child.add(id);
      child.add(err);
      return objectMapper.createObjectNode().put("type","invalid_block_rule").set("value", child);
    }
  }

  public static final class InvalidBlockScope extends LogicError {
    public final long id;
    public final String err;

    public InvalidBlockScope(long id, String e) {
      this.id = id;
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
      InvalidBlockScope other = (InvalidBlockScope) o;
      return id == other.id && err.equals(other.err);
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, err);
    }

    @Override
    public String toString() {
      return "LogicError.InvalidBlockScope{ id: " + id + ", error: " + err + " }";
    }

    @Override
    public JsonNode toJson() {
      ArrayNode child = objectMapper.createArrayNode();
      child.add(id);
      child.add(err);
      return objectMapper.createObjectNode().put("type", "invalid_block_scope").set("value", child);
    }
  }

  public static final class Unauthorized extends LogicError {
    public final List<FailedCheck> errors;
    public final MatchedPolicy policy;

    public Unauthorized(MatchedPolicy policy, List<FailedCheck> errors) {
      this.errors = errors;
      this.policy = policy;
    }

    public Optional<List<FailedCheck>> getFailedChecks() {
      return Optional.of(errors);
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
    public JsonNode toJson() {
      ArrayNode checks = objectMapper.createArrayNode();
      for (FailedCheck t : this.errors) {
        checks.add(t.toJson());
      }

      ObjectNode unauthorized = objectMapper.createObjectNode();
      unauthorized.set("policy", policy.toJson());
      unauthorized.set("checks", checks);
      return objectMapper.createObjectNode().put("type", "unauthorized").set("value", unauthorized);
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
    public Optional<List<FailedCheck>> getFailedChecks() {
      return Optional.of(errors);
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

    @SuppressWarnings("checkstyle:RegexpSinglelineJava")
    @Override
    public String toString() {
      return "NoMatchingPolicy{ }";
    }

    @Override
    public JsonNode toJson() {
      ArrayNode errors = objectMapper.createArrayNode();
      for (FailedCheck t : this.errors) {
        errors.add(t.toJson());
      }
      return objectMapper.createObjectNode().put("type", "no_matching_policy").set("value", errors);
    }
  }

  public static final class AuthorizerNotEmpty extends LogicError {

    public AuthorizerNotEmpty() {}

    @Override
    public JsonNode toJson() {
      return objectMapper.createObjectNode().put("type", "authorizer_not_empty");
    }

    @Override
    public String toString() {
      return "AuthorizerNotEmpty";
    }
  }

  public abstract static class MatchedPolicy {
    public abstract JsonNode toJson();

    public static final class Allow extends MatchedPolicy {
      public final long nb;

      public Allow(long nb) {
        this.nb = nb;
      }

      @Override
      public String toString() {
        return "Allow(" + this.nb + ")";
      }

      @Override
      public JsonNode toJson() {
        return objectMapper.createObjectNode().put("type", "allow").put("value", nb);
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

      @Override
      public JsonNode toJson() {
        return objectMapper.createObjectNode().put("type", "deny").put("value", nb);
      }
    }
  }
}
