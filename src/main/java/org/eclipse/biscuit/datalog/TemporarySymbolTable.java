package org.eclipse.biscuit.datalog;

import static org.eclipse.biscuit.datalog.SymbolTable.DEFAULT_SYMBOLS_OFFSET;

import io.vavr.control.Option;
import java.util.ArrayList;
import java.util.List;

public final class TemporarySymbolTable {
  private SymbolTable base;
  private int offset;
  private List<String> symbols;

  public TemporarySymbolTable(SymbolTable base) {
    this.offset = DEFAULT_SYMBOLS_OFFSET + base.currentOffset();
    this.base = base;
    this.symbols = new ArrayList<>();
  }

  public Option<String> getSymbol(int i) {
    if (i >= this.offset) {
      if (i - this.offset < this.symbols.size()) {
        return Option.some(this.symbols.get(i - this.offset));
      } else {
        return Option.none();
      }
    } else {
      return this.base.getSymbol(i);
    }
  }

  public long insert(final String symbol) {
    Option<Long> opt = this.base.get(symbol);
    if (opt.isDefined()) {
      return opt.get();
    }

    int index = this.symbols.indexOf(symbol);
    if (index != -1) {
      return (long) (this.offset + index);
    }
    this.symbols.add(symbol);
    return this.symbols.size() - 1 + this.offset;
  }
}
