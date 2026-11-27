package org.eclipse.biscuit.token.builder;

import java.util.Comparator;
import org.eclipse.biscuit.datalog.SymbolTable;

public abstract class MapKey extends Term {
  public abstract org.eclipse.biscuit.datalog.MapKey convertMapKey(SymbolTable symbolTable);

  public abstract org.eclipse.biscuit.datalog.Term.MapKeyType getMapKeyType();

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
              return Long.compare(((Term.Integer) m1).getValue(), ((Term.Integer) m2).getValue());
            case STRING:
              return ((Term.Str) m1).getValue().compareTo(((Term.Str) m2).getValue());
            default:
              throw new UnknownError("Unexpected MapKey " + m1 + m2);
          }
        }
      };
}
