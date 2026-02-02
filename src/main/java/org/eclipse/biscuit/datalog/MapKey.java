package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;

public abstract class MapKey extends Term {
  public abstract Schema.MapKey serializeMapKey();

  public abstract org.eclipse.biscuit.token.builder.MapKey toMapKey(SymbolTable symbolTable);

  public static Result<MapKey, Error.FormatError> deserializeMapKeyEnum(Schema.MapKey mapKey) {
    if (mapKey.hasInteger()) {
      return Term.Integer.deserializeMapKey(mapKey);
    } else if (mapKey.hasString()) {
      return Term.Str.deserializeMapKey(mapKey);
    } else {
      return Result.err(new Error.FormatError.DeserializationError("invalid MapKey kind"));
    }
  }
}
