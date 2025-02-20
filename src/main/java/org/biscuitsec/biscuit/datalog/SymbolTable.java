package org.biscuitsec.biscuit.datalog;

import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.expressions.Expression;
import org.biscuitsec.biscuit.token.builder.Utils;
import io.vavr.control.Option;

import java.io.Serializable;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public final class SymbolTable implements Serializable {
    public final static short DEFAULT_SYMBOLS_OFFSET = 1024;

    private final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ISO_INSTANT;

    public String fromEpochIsoDate(long epochSec) {
        return Instant.ofEpochSecond(epochSec).atOffset(ZoneOffset.ofTotalSeconds(0)).format(dateTimeFormatter);
    }

    /**
     * According to <a href="https://github.com/biscuit-auth/biscuit/blob/master/SPECIFICATIONS.md#symbol-table">the specification</a>,
     * We need two symbols tables:
     * * one for the defaults symbols indexed from 0 et 1023 in <code>defaultSymbols</code> list
     * * one for the usages symbols indexed from 1024 in <code>symbols</code> list
     */
    public final static List<String> DEFAULT_SYMBOLS = List.of(
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
            "query"
    );
    public final List<String> symbols;
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

    public int currentOffset() {
        return this.symbols.size();
    }
    public int currentPublicKeyOffset() {
        return this.publicKeys.size();
    }

    public List<PublicKey> getPublicKeys() {
        return publicKeys;
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

    public Term add(final String symbol) {
        return new Term.Str(this.insert(symbol));
    }

    public Option<Long> get(final String symbol) {
        // looking for symbol in default symbols
        long index = this.DEFAULT_SYMBOLS.indexOf(symbol);
        if (index == -1) {
            // looking for symbol in usages defined symbols
            index = this.symbols.indexOf(symbol);
            if (index == -1) {
                return Option.none();
            } else {
                return Option.some(index + DEFAULT_SYMBOLS_OFFSET);
            }
        } else {
            return Option.some(index);
        }
    }

    public Option<String> getSymbol(int i) {
        if (i >= 0 && i < this.DEFAULT_SYMBOLS.size() && i < DEFAULT_SYMBOLS_OFFSET) {
            return Option.some(this.DEFAULT_SYMBOLS.get(i));
        } else if (i >= DEFAULT_SYMBOLS_OFFSET && i < this.symbols.size() + DEFAULT_SYMBOLS_OFFSET) {
            return Option.some(this.symbols.get(i - DEFAULT_SYMBOLS_OFFSET));
        } else {
            return Option.none();
        }
    }

    public Option<PublicKey> getPublicKey(int i) {
        if (i >= 0 && i < this.publicKeys.size()) {
            return Option.some(this.publicKeys.get(i));
        } else {
            return Option.none();
        }
    }

    public String formatRule(final Rule r) {
        String res = this.formatPredicate(r.head());
        res += " <- " + this.formatRuleBody(r);

        return res;
    }

    public String formatRuleBody(final Rule r) {
        final List<String> preds = r.body().stream().map((p) -> this.formatPredicate(p)).collect(Collectors.toList());
        final List<String> expressions = r.expressions().stream().map((c) -> this.formatExpression(c)).collect(Collectors.toList());

        String res = String.join(", ", preds);
        if (!expressions.isEmpty()) {
            if (!preds.isEmpty()) {
                res += ", ";
            }
            res += String.join(", ", expressions);
        }

        if(!r.scopes().isEmpty()) {
            res += " trusting ";
            final List<String> scopes = r.scopes().stream().map((s) -> this.formatScope(s)).collect(Collectors.toList());
            res += String.join(", ", scopes);
        }
        return res;
    }

    public String formatExpression(final Expression e) {
        return e.print(this).get();
    }

    public String formatScope(final Scope scope) {
        switch(scope.kind) {
            case Authority:
                return "authority";
            case Previous:
                return "previous";
            case PublicKey:
                Option<PublicKey> pk = this.getPublicKey((int) scope.publicKey);
                if(pk.isDefined()) {
                    return pk.get().toString();
                }
        }
        return "<"+ scope.publicKey+"?>";
    }

    public String formatPredicate(final Predicate p) {
        List<String> ids = p.terms().stream().map((t) -> {
            return this.formatTerm(t);
        }).collect(Collectors.toList());
        return Optional.ofNullable(this.formatSymbol((int) p.name())).orElse("<?>") + "(" + String.join(", ", ids) + ")";
    }

    public String formatTerm(final Term i) {
        if (i instanceof Term.Variable) {
            return "$" + this.formatSymbol((int) ((Term.Variable) i).value());
        } else if(i instanceof Term.Bool) {
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
            final List<String> values = ((Term.Set) i).value().stream().map((v) -> this.formatTerm(v)).collect(Collectors.toList());
            return "[" + String.join(", ", values) + "]";
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
            case One:
                prefix = "check if ";
                break;
            case All:
                prefix = "check all ";
                break;
            default:
                prefix = "check if ";
                break;
        }
        final List<String> queries = c.queries().stream().map((q) -> this.formatRuleBody(q)).collect(Collectors.toList());
        return prefix + String.join(" or ", queries);
    }

    public String formatWorld(final World w) {
        final List<String> facts = w.facts().stream().map((f) -> this.formatFact(f)).collect(Collectors.toList());
        final List<String> rules = w.rules().stream().map((r) -> this.formatRule(r)).collect(Collectors.toList());

        StringBuilder b = new StringBuilder();
        b.append("World {\n\tfacts: [\n\t\t");
        b.append(String.join(",\n\t\t", facts));
        b.append("\n\t],\n\trules: [\n\t\t");
        b.append(String.join(",\n\t\t", rules));
        b.append("\n\t]\n}");

        return b.toString();
    }

    public String formatSymbol(int i) {
        return getSymbol(i).getOrElse("<" + i + "?>");
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
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SymbolTable that = (SymbolTable) o;

        if (!dateTimeFormatter.equals(that.dateTimeFormatter)) return false;
        if (!symbols.equals(that.symbols)) return false;
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
        return "SymbolTable{" +
                "symbols=" + symbols +
                ", publicKeys=" + publicKeys +
                '}';
    }
}
