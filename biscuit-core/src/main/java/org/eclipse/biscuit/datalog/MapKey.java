package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.DeserializationLimit;

public abstract class MapKey extends Term {
  public abstract Schema.MapKey serializeMapKey();

  public abstract org.eclipse.biscuit.token.builder.MapKey toMapKey(SymbolTable symbolTable);

  public static Result<MapKey, Error.FormatError> deserializeMapKeyEnum(
      Schema.MapKey mapKey, DeserializationLimit.PerBlock limits, SymbolTable symbols) {
    var allowedTypes = limits.getAllowedMapKeyTypes();
    var type = mapKeyType(mapKey.getContentCase());
    if (allowedTypes != null && type != null && !allowedTypes.contains(type)) {
      return Result.err(
          new Error.FormatError.DeserializationLimitError(
              Error.FormatError.DeserializationLimitError.Reason.MAP_KEY_TYPE_NOT_ALLOWED));
    }

    switch (mapKey.getContentCase()) {
      case INTEGER:
        return Term.Integer.deserializeMapKey(mapKey);
      case STRING:
        var stringError = limits.checkString(symbols, mapKey.getString());
        if (stringError != null) {
          return Result.err(stringError);
        }
        return Term.Str.deserializeMapKey(mapKey);
      default:
        return Result.err(new Error.FormatError.DeserializationError("invalid MapKey kind"));
    }
  }

  private static DeserializationLimit.MapKeyType mapKeyType(Schema.MapKey.ContentCase content) {
    switch (content) {
      case INTEGER:
        return DeserializationLimit.MapKeyType.INTEGER;
      case STRING:
        return DeserializationLimit.MapKeyType.STRING;
      case CONTENT_NOT_SET:
        return null;
      default:
        throw new IllegalStateException("unhandled map key kind " + content);
    }
  }
}
