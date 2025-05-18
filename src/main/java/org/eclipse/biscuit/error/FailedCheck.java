/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.error;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.util.List;
import java.util.Objects;

public class FailedCheck {

  /**
   * serialize to Json Object
   *
   * @return json object
   */
  public JsonElement toJson() {
    return new JsonObject();
  }

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
      return "Block(FailedBlockCheck " + new Gson().toJson(toJson()) + ")";
    }

    @Override
    public JsonElement toJson() {
      JsonObject jo = new JsonObject();
      jo.addProperty("block_id", blockId);
      jo.addProperty("check_id", checkId);
      jo.addProperty("rule", rule);
      JsonObject block = new JsonObject();
      block.add("Block", jo);
      return block;
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
    public JsonElement toJson() {
      JsonObject jo = new JsonObject();
      jo.addProperty("check_id", checkId);
      jo.addProperty("rule", rule);
      JsonObject authorizer = new JsonObject();
      authorizer.add("Authorizer", jo);
      return authorizer;
    }
  }

  public static final class ParseErrors extends FailedCheck {}

  public static class LanguageError extends FailedCheck {
    public static final class ParseError extends LanguageError {

      @Override
      public JsonElement toJson() {
        return new JsonPrimitive("ParseError");
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
      public JsonElement toJson() {
        JsonObject authorizer = new JsonObject();
        JsonArray ja = new JsonArray();
        for (String s : invalidVariables) {
          ja.add(s);
        }
        authorizer.add("InvalidVariables", ja);
        return authorizer;
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
      public JsonElement toJson() {
        JsonObject authorizer = new JsonObject();
        authorizer.add("UnknownVariable", new JsonPrimitive(message));
        return authorizer;
      }
    }
  }
}
