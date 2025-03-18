package org.eclipse.biscuit.datalog;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

import biscuit.format.schema.Schema;
import io.vavr.control.Either;
import org.eclipse.biscuit.error.Error;

public final class Scope {
  public enum Kind {
    Authority,
    Previous,
    PublicKey
  }

  private Kind kind;
  private long publicKey;

  private Scope(Kind kind, long publicKey) {
    this.kind = kind;
    this.publicKey = publicKey;
  }

  public static Scope authority() {
    return new Scope(Kind.Authority, 0);
  }

  public static Scope previous() {
    return new Scope(Kind.Previous, 0);
  }

  public static Scope publicKey(long publicKey) {
    return new Scope(Kind.PublicKey, publicKey);
  }

  public Kind kind() {
    return kind;
  }

  public long getPublicKey() {
    return publicKey;
  }

  public Schema.Scope serialize() {
    Schema.Scope.Builder b = Schema.Scope.newBuilder();

    switch (this.kind) {
      case Authority:
        b.setScopeType(Schema.Scope.ScopeType.Authority);
        break;
      case Previous:
        b.setScopeType(Schema.Scope.ScopeType.Previous);
        break;
      case PublicKey:
        b.setPublicKey(this.publicKey);
        break;
      default:
    }

    return b.build();
  }

  public static Either<Error.FormatError, Scope> deserialize(Schema.Scope scope) {
    if (scope.hasPublicKey()) {
      long publicKey = scope.getPublicKey();
      return Right(Scope.publicKey(publicKey));
    }
    if (scope.hasScopeType()) {
      switch (scope.getScopeType()) {
        case Authority:
          return Right(Scope.authority());
        case Previous:
          return Right(Scope.previous());
        default:
          return Left(new Error.FormatError.DeserializationError("invalid Scope"));
      }
    }
    return Left(new Error.FormatError.DeserializationError("invalid Scope"));
  }

  @Override
  public String toString() {
    return "Scope{" + "kind=" + kind + ", publicKey=" + publicKey + '}';
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

    if (publicKey != scope.publicKey) {
      return false;
    }
    return kind == scope.kind;
  }

  @Override
  public int hashCode() {
    int result = kind != null ? kind.hashCode() : 0;
    result = 31 * result + (int) (publicKey ^ (publicKey >>> 32));
    return result;
  }
}
