package org.eclipse.biscuit.datalog;

import biscuit.format.schema.Schema;
import java.util.Comparator;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.DeserializationLimit;

public abstract class MapKey extends Term {
  public abstract Schema.MapKey serializeMapKey();

  public abstract org.eclipse.biscuit.token.builder.MapKey toMapKey(SymbolTable symbolTable);

  public abstract MapKeyType getMapKeyType();

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

  public static Comparator<MapKey> comparator =
      new Comparator<MapKey>() {
        @Override
        public int compare(MapKey m1, MapKey m2) {
          int c = m1.getMapKeyType().compareTo(m2.getMapKeyType());
          if (c != 0) {
            return c;
          }
          switch (m1.getMapKeyType()) {
            case INTEGER:
              return Long.compare(((Term.Integer) m1).value(), ((Term.Integer) m2).value());
            case STRING:
              return Long.compare(((Term.Str) m1).value(), ((Term.Str) m2).value());
            default:
              throw new UnknownError("Unexpected MapKey " + m1 + m2);
          }
        }
      };

  private static MapKeyType mapKeyType(Schema.MapKey.ContentCase content) {
    switch (content) {
      case INTEGER:
        return MapKeyType.INTEGER;
      case STRING:
        return MapKeyType.STRING;
      case CONTENT_NOT_SET:
        return null;
      default:
        throw new IllegalStateException("unhandled map key kind " + content);
    }
  }
}
