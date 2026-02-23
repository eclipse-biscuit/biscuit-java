/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.error;

import java.util.Objects;

public abstract class Result<T, E> {
  public boolean isOk() {
    return false;
  }

  public boolean isErr() {
    return false;
  }

  public T getOk() {
    throw new IllegalStateException("Result is not ok");
  }

  public E getErr() {
    throw new IllegalStateException("Result is not error");
  }

  private static final class Ok<T, E> extends Result<T, E> {
    T okValue;

    Ok(T okValue) {
      this.okValue = okValue;
    }

    @Override
    public boolean isOk() {
      return true;
    }

    @Override
    public T getOk() {
      return okValue;
    }

    @Override
    public boolean equals(Object obj) {
      return obj == this || obj instanceof Ok && Objects.equals(okValue, ((Ok<?, ?>) obj).okValue);
    }
  }

  private static final class Err<T, E> extends Result<T, E> {
    E errorValue;

    Err(E errorValue) {
      this.errorValue = errorValue;
    }

    @Override
    public boolean isErr() {
      return true;
    }

    @Override
    public E getErr() {
      return errorValue;
    }

    @Override
    public boolean equals(Object obj) {
      return obj == this
          || obj instanceof Err && Objects.equals(errorValue, ((Err<?, ?>) obj).errorValue);
    }
  }

  public static <T, E> Result<T, E> ok(T okValue) {
    return new Ok<>(okValue);
  }

  public static <T, E> Result<T, E> err(E errorValue) {
    return new Err<>(errorValue);
  }
}
