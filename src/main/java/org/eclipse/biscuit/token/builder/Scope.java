/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder;

import java.util.Objects;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.SymbolTable;

public final class Scope {
  enum Kind {
    Authority,
    Previous,
    PublicKey,
    Parameter,
  }

  private Kind kind;
  private PublicKey publicKey;
  private String parameter;

  private Scope(Kind kind) {
    this.kind = kind;
    this.publicKey = null;
    this.parameter = "";
  }

  private Scope(Kind kind, PublicKey publicKey) {
    this.kind = kind;
    this.publicKey = publicKey;
    this.parameter = "";
  }

  private Scope(Kind kind, String parameter) {
    this.kind = kind;
    this.publicKey = null;
    this.parameter = parameter;
  }

  public static Scope authority() {
    return new Scope(Kind.Authority);
  }

  public static Scope previous() {
    return new Scope(Kind.Previous);
  }

  public static Scope publicKey(PublicKey publicKey) {
    return new Scope(Kind.PublicKey, publicKey);
  }

  public static Scope parameter(String parameter) {
    return new Scope(Kind.Parameter, parameter);
  }

  public org.eclipse.biscuit.datalog.Scope convert(SymbolTable symbolTable) {
    switch (this.kind) {
      case Authority:
        return org.eclipse.biscuit.datalog.Scope.authority();
      case Previous:
        return org.eclipse.biscuit.datalog.Scope.previous();
      case Parameter:
        // FIXME
        return null;
      // throw new Exception("Remaining parameter: " + this.parameter);
      case PublicKey:
        return org.eclipse.biscuit.datalog.Scope.publicKey(symbolTable.insert(this.publicKey));
      default:
        return null;
    }
  }

  public static Scope convertFrom(
          org.eclipse.biscuit.datalog.Scope scope, SymbolTable symbolTable) {
    switch (scope.kind()) {
      case Authority:
        return new Scope(Kind.Authority);
      case Previous:
        return new Scope(Kind.Previous);
      case PublicKey:
        // FIXME error management should bubble up here
        return new Scope(
            Kind.PublicKey, symbolTable.getPublicKey((int) scope.getPublicKey()).get());
      default:
        return null;
    }

    // FIXME error management should bubble up here
    // throw new Exception("panic");
    // return null;

  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Scope scope = (Scope) o;

    if (kind != scope.kind) {
      return false;
    }
    if (!Objects.equals(publicKey, scope.publicKey)) {
      return false;
    }
    return Objects.equals(parameter, scope.parameter);
  }

  @Override
  public int hashCode() {
    int result = kind.hashCode();
    result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
    result = 31 * result + (parameter != null ? parameter.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    switch (this.kind) {
      case Authority:
        return "authority";
      case Previous:
        return "previous";
      case Parameter:
        return "{" + this.parameter + "}";
      case PublicKey:
        return this.publicKey.toString();
      default:
    }
    return null;
  }
}
