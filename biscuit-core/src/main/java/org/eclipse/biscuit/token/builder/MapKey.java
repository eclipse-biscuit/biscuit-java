package org.eclipse.biscuit.token.builder;

import org.eclipse.biscuit.datalog.SymbolTable;

public abstract class MapKey extends Term {
  public abstract org.eclipse.biscuit.datalog.MapKey convertMapKey(SymbolTable symbolTable);
}
