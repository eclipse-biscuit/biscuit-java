/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder.parser;

public final class Error extends Exception {
  String input;
  String message;

  public Error(String input, String message) {
    super(message);
    this.input = input;
    this.message = message;
  }

  @Override
  public String toString() {
    return "Error{" + "input='" + input + '\'' + ", message='" + message + '\'' + '}';
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Error error = (Error) o;

    if (input != null ? !input.equals(error.input) : error.input != null) {
      return false;
    }
    return message != null ? message.equals(error.message) : error.message == null;
  }

  @Override
  public int hashCode() {
    int result = input != null ? input.hashCode() : 0;
    result = 31 * result + (message != null ? message.hashCode() : 0);
    return result;
  }
}
