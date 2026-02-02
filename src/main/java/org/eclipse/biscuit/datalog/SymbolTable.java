/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.io.Serializable;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.expressions.Expression;
import org.eclipse.biscuit.token.builder.Utils;

public final class SymbolTable implements Serializable {
  public static final short DEFAULT_SYMBOLS_OFFSET = 1024;

  private final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ISO_INSTANT;

  public String fromEpochIsoDate(long epochSec) {
    return Instant.ofEpochSecond(epochSec)
        .atOffset(ZoneOffset.ofTotalSeconds(0))
        .format(dateTimeFormatter);
  }

  /**
   * According to <a
   * href="https://github.com/biscuit-auth/biscuit/blob/master/SPECIFICATIONS.md#symbol-table">the
   * specification</a>, We need two symbols tables: * one for the defaults symbols indexed from 0 et
   * 1023 in <code>defaultSymbols</code> list * one for the usages symbols indexed from 1024 in
   * <code>symbols</code> list
   */
  public static final List<String> DEFAULT_SYMBOLS =
      List.of(
          "read",
          "write",
          "resource",
          "operation",
          "right",
          "time",
          "role",
          "owner",
          "tenant",
          "namespace",
          "user",
          "team",
          "service",
          "admin",
          "email",
          "group",
          "member",
          "ip_address",
          "client",
          "client_ip",
          "domain",
          "path",
          "version",
          "cluster",
          "node",
          "hostname",
          "nonce",
          "query");

  private final List<String> symbols;
  private final List<PublicKey> publicKeys;

  public long insert(final String symbol) {
    int index = this.DEFAULT_SYMBOLS.indexOf(symbol);
    if (index == -1) {
      index = this.symbols.indexOf(symbol);
      if (index == -1) {
        this.symbols.add(symbol);
        return this.symbols.size() - 1 + DEFAULT_SYMBOLS_OFFSET;
      } else {
        return index + DEFAULT_SYMBOLS_OFFSET;
      }
    } else {
      return index;
    }
  }

  public long insert(final PublicKey publicKey) {
    int index = this.publicKeys.indexOf(publicKey);
    if (index == -1) {
      this.publicKeys.add(publicKey);
      return this.publicKeys.size() - 1;
    } else {
      return index;
    }
  }

  public int currentOffset() {
    return this.symbols.size();
  }

  public int currentPublicKeyOffset() {
    return this.publicKeys.size();
  }

  public List<PublicKey> getPublicKeys() {
    return publicKeys;
  }

  public Term add(final String symbol) {
    return new Term.Str(this.insert(symbol));
  }

  public Optional<Long> get(final String symbol) {
    // looking for symbol in default symbols
    long index = this.DEFAULT_SYMBOLS.indexOf(symbol);
    if (index == -1) {
      // looking for symbol in usages defined symbols
      index = this.symbols.indexOf(symbol);
      if (index == -1) {
        return Optional.empty();
      } else {
        return Optional.of(index + DEFAULT_SYMBOLS_OFFSET);
      }
    } else {
      return Optional.of(index);
    }
  }

  public Optional<String> getSymbol(int i) {
    if (i >= 0 && i < this.DEFAULT_SYMBOLS.size() && i < DEFAULT_SYMBOLS_OFFSET) {
      return Optional.of(this.DEFAULT_SYMBOLS.get(i));
    } else if (i >= DEFAULT_SYMBOLS_OFFSET && i < this.symbols.size() + DEFAULT_SYMBOLS_OFFSET) {
      return Optional.of(this.symbols.get(i - DEFAULT_SYMBOLS_OFFSET));
    } else {
      return Optional.empty();
    }
  }

  public Optional<PublicKey> getPublicKey(int i) {
    if (i >= 0 && i < this.publicKeys.size()) {
      return Optional.of(this.publicKeys.get(i));
    } else {
      return Optional.empty();
    }
  }

  public String formatRule(final Rule r) {
    String res = this.formatPredicate(r.head());
    res += " <- " + this.formatRuleBody(r);

    return res;
  }

  public String formatRuleBody(final Rule r) {
    final List<String> preds =
        r.body().stream().map((p) -> this.formatPredicate(p)).collect(Collectors.toList());
    final List<String> expressions =
        r.expressions().stream().map((c) -> this.formatExpression(c)).collect(Collectors.toList());

    String res = String.join(", ", preds);
    if (!expressions.isEmpty()) {
      if (!preds.isEmpty()) {
        res += ", ";
      }
      res += String.join(", ", expressions);
    }

    if (!r.scopes().isEmpty()) {
      res += " trusting ";
      final List<String> scopes =
          r.scopes().stream().map((s) -> this.formatScope(s)).collect(Collectors.toList());
      res += String.join(", ", scopes);
    }
    return res;
  }

  public String formatExpression(final Expression e) {
    return e.print(this).get();
  }

  public String formatScope(final Scope scope) {
    switch (scope.kind()) {
      case Authority:
        return "authority";
      case Previous:
        return "previous";
      case PublicKey:
        Optional<PublicKey> pk = this.getPublicKey((int) scope.getPublicKey());
        if (pk.isPresent()) {
          return pk.get().toString();
        } else {
          return "<" + scope.getPublicKey() + "?>";
        }
      default:
        return "<" + scope.getPublicKey() + "?>";
    }
  }

  public String formatPredicate(final Predicate p) {
    List<String> ids =
        p.terms().stream()
            .map(
                (t) -> {
                  return this.formatTerm(t);
                })
            .collect(Collectors.toList());
    return Optional.ofNullable(this.formatSymbol((int) p.name())).orElse("<?>")
        + "("
        + String.join(", ", ids)
        + ")";
  }

  public String formatTerm(final Term i) {
    if (i instanceof Term.Variable) {
      return "$" + this.formatSymbol((int) ((Term.Variable) i).value());
    } else if (i instanceof Term.Bool) {
      return i.toString();
    } else if (i instanceof Term.Date) {
      return fromEpochIsoDate(((Term.Date) i).value());
    } else if (i instanceof Term.Integer) {
      return "" + ((Term.Integer) i).value();
    } else if (i instanceof Term.Str) {
      return "\"" + this.formatSymbol((int) ((Term.Str) i).value()) + "\"";
    } else if (i instanceof Term.Bytes) {
      return "hex:" + Utils.byteArrayToHexString(((Term.Bytes) i).value()).toLowerCase();
    } else if (i instanceof Term.Set) {
      final List<String> values =
          ((Term.Set) i)
              .value().stream().map((v) -> this.formatTerm(v)).collect(Collectors.toList());
      if (values.isEmpty()) {
        return "{,}";
      } else {
        Collections.sort(values);
        return "{" + String.join(", ", values) + "}";
      }
    } else if (i instanceof Term.Null) {
      return "null";
    } else if (i instanceof Term.Array) {
      final List<String> values =
          ((Term.Array) i)
              .value().stream().map((v) -> this.formatTerm(v)).collect(Collectors.toList());
      return "[" + String.join(", ", values) + "]";
    } else if (i instanceof Term.Map) {
      ArrayList<String> entries = new ArrayList();
      for (Map.Entry<MapKey, Term> entry : ((Term.Map) i).value().entrySet()) {
        entries.add(formatTerm(entry.getKey()) + ": " + formatTerm(entry.getValue()));
      }
      Collections.sort(entries);
      return "{" + String.join(", ", entries) + "}";
    } else {
      return "???";
    }
  }

  public String formatFact(final Fact f) {
    return this.formatPredicate(f.predicate());
  }

  public String formatCheck(final Check c) {
    String prefix;
    switch (c.kind()) {
      case ONE:
        prefix = "check if ";
        break;
      case ALL:
        prefix = "check all ";
        break;
      case REJECT:
        prefix = "reject if ";
        break;
      default:
        prefix = "check if ";
        break;
    }
    final List<String> queries =
        c.queries().stream().map((q) -> this.formatRuleBody(q)).collect(Collectors.toList());
    return prefix + String.join(" or ", queries);
  }

  public String formatWorld(final World w) {
    final List<String> facts =
        w.getFacts().stream().map((f) -> this.formatFact(f)).collect(Collectors.toList());
    final List<String> rules =
        w.getRules().stream().map((r) -> this.formatRule(r)).collect(Collectors.toList());

    StringBuilder b = new StringBuilder();
    b.append("World {\n\tfacts: [\n\t\t");
    b.append(String.join(",\n\t\t", facts));
    b.append("\n\t],\n\trules: [\n\t\t");
    b.append(String.join(",\n\t\t", rules));
    b.append("\n\t]\n}");

    return b.toString();
  }

  public String formatSymbol(int i) {
    return getSymbol(i).orElse("<" + i + "?>");
  }

  public SymbolTable() {
    this.symbols = new ArrayList<>();
    this.publicKeys = new ArrayList<>();
  }

  public SymbolTable(SymbolTable s) {
    this.symbols = new ArrayList<>();
    symbols.addAll(s.symbols);
    this.publicKeys = new ArrayList<>();
    publicKeys.addAll(s.publicKeys);
  }

  public SymbolTable(List<String> symbols) {
    this.symbols = new ArrayList<>(symbols);
    this.publicKeys = new ArrayList<>();
  }

  public SymbolTable(SymbolTable sourceSymbolTable, List<PublicKey> publicKeys) {
    this(sourceSymbolTable.symbols, publicKeys);
  }

  public SymbolTable(List<String> symbols, List<PublicKey> publicKeys) {
    this.symbols = new ArrayList<>();
    this.symbols.addAll(symbols);
    this.publicKeys = new ArrayList<>();
    this.publicKeys.addAll(publicKeys);
  }

  public List<String> getAllSymbols() {
    ArrayList<String> allSymbols = new ArrayList<>();
    allSymbols.addAll(DEFAULT_SYMBOLS);
    allSymbols.addAll(symbols);
    return allSymbols;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    SymbolTable that = (SymbolTable) o;

    if (!dateTimeFormatter.equals(that.dateTimeFormatter)) {
      return false;
    }
    if (!symbols.equals(that.symbols)) {
      return false;
    }
    return publicKeys.equals(that.publicKeys);
  }

  @Override
  public int hashCode() {
    int result = dateTimeFormatter.hashCode();
    result = 31 * result + symbols.hashCode();
    result = 31 * result + publicKeys.hashCode();
    return result;
  }

  @Override
  public String toString() {
    return "SymbolTable{" + "symbols=" + symbols + ", publicKeys=" + publicKeys + '}';
  }

  public List<String> symbols() {
    return Collections.unmodifiableList(symbols);
  }

  public boolean disjoint(final SymbolTable other) {
    return Collections.disjoint(this.symbols, other.symbols);
  }
}
