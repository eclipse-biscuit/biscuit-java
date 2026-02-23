/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.error;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.util.List;
import java.util.Objects;

public abstract class FailedCheck {
  static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * serialize to Json Object
   *
   * @return json object
   */
  public abstract JsonNode toJson();

  public static final class FailedBlock extends FailedCheck {
    public final long blockId;
    public final long checkId;
    public final String rule;

    public FailedBlock(long blockId, long checkId, String rule) {
      this.blockId = blockId;
      this.checkId = checkId;
      this.rule = rule;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      FailedBlock b = (FailedBlock) o;
      return blockId == b.blockId && checkId == b.checkId && rule.equals(b.rule);
    }

    @Override
    public int hashCode() {
      return Objects.hash(blockId, checkId, rule);
    }

    @Override
    public String toString() {
      try {
        return "Block(FailedBlockCheck " + objectMapper.writeValueAsString(toJson()) + ")";
      } catch (JsonProcessingException e) {
        throw new IllegalStateException(e);
      }
    }

    @Override
    public JsonNode toJson() {
      ObjectNode child = objectMapper.createObjectNode();
      child.set("block_id", LongNode.valueOf(this.blockId));
      child.set("check_id", LongNode.valueOf(this.checkId));
      child.set("rule", TextNode.valueOf(this.rule));
      return objectMapper.createObjectNode().set("Block", child);
    }
  }

  public static final class FailedAuthorizer extends FailedCheck {
    public final long checkId;
    public final String rule;

    public FailedAuthorizer(long checkId, String rule) {
      this.checkId = checkId;
      this.rule = rule;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      FailedAuthorizer b = (FailedAuthorizer) o;
      return checkId == b.checkId && rule.equals(b.rule);
    }

    @Override
    public int hashCode() {
      return Objects.hash(checkId, rule);
    }

    @Override
    public String toString() {
      return "FailedCaveat.FailedAuthorizer { check_id: " + checkId + ", rule: " + rule + " }";
    }

    @Override
    public JsonNode toJson() {
      ObjectNode child = objectMapper.createObjectNode();
      child.set("check_id", LongNode.valueOf(this.checkId));
      child.set("rule", TextNode.valueOf(this.rule));
      return objectMapper.createObjectNode().set("Authorizer", child);
    }
  }

  public abstract static class LanguageError extends FailedCheck {
    public static final class ParseError extends LanguageError {

      @Override
      public JsonNode toJson() {
        return TextNode.valueOf("ParseError");
      }
    }

    public static final class Builder extends LanguageError {
      List<String> invalidVariables;

      public Builder(List<String> invalidVariables) {
        this.invalidVariables = invalidVariables;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        Builder b = (Builder) o;
        return invalidVariables == b.invalidVariables
            && invalidVariables.equals(b.invalidVariables);
      }

      @Override
      public int hashCode() {
        return Objects.hash(invalidVariables);
      }

      @Override
      public String toString() {
        return "InvalidVariables { message: " + invalidVariables + " }";
      }

      @Override
      public JsonNode toJson() {
        ArrayNode child = objectMapper.createArrayNode();
        for (String s : invalidVariables) {
          child.add(s);
        }
        return objectMapper.createObjectNode().set("InvalidVariables", child);
      }
    }

    public static final class UnknownVariable extends LanguageError {
      String message;

      public UnknownVariable(String message) {
        this.message = message;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) {
          return true;
        }
        if (o == null || getClass() != o.getClass()) {
          return false;
        }
        UnknownVariable b = (UnknownVariable) o;
        return this.message == b.message && message.equals(b.message);
      }

      @Override
      public int hashCode() {
        return Objects.hash(message);
      }

      @Override
      public String toString() {
        return "LanguageError.UnknownVariable { message: " + message + " }";
      }

      @Override
      public JsonNode toJson() {
        return objectMapper.createObjectNode().put("UnknownVariable", message);
      }
    }
  }
}
