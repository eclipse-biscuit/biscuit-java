package org.biscuitsec.biscuit.token;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.expressions.Expression;
import org.biscuitsec.biscuit.datalog.expressions.Op;
import org.biscuitsec.biscuit.datalog.Check;
import org.biscuitsec.biscuit.datalog.Fact;
import org.biscuitsec.biscuit.datalog.Rule;
import org.biscuitsec.biscuit.datalog.SchemaVersion;
import org.biscuitsec.biscuit.datalog.Scope;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.format.SerializedBiscuit;
import com.google.protobuf.InvalidProtocolBufferException;
import io.vavr.control.Either;
import io.vavr.control.Option;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

/**
 * Represents a token's block with its checks
 */
public class Block {
    final SymbolTable symbols;
    final String context;
    final List<Fact> facts;
    final List<Rule> rules;
    final List<Check> checks;
    final List<Scope> scopes;
    final List<PublicKey> publicKeys;
    Option<PublicKey> externalKey;
    long version;

    /**
     * creates a new block
     *
     * @param baseSymbols
     */
    public Block(SymbolTable baseSymbols) {
        this.symbols = baseSymbols;
        this.context = "";
        this.facts = new ArrayList<>();
        this.rules = new ArrayList<>();
        this.checks = new ArrayList<>();
        this.scopes = new ArrayList<>();
        this.publicKeys = new ArrayList<>();
        this.externalKey = Option.none();
    }

    /**
     * creates a new block
     *
     * @param baseSymbols
     * @param facts
     * @param checks
     */
    public Block(SymbolTable baseSymbols, String context, List<Fact> facts, List<Rule> rules, List<Check> checks,
                 List<Scope> scopes, List<PublicKey> publicKeys, Option<PublicKey> externalKey, int version) {
        this.symbols = baseSymbols;
        this.context = context;
        this.facts = facts;
        this.rules = rules;
        this.checks = checks;
        this.scopes = scopes;
        this.publicKeys = publicKeys;
        this.externalKey = externalKey;
    }

    public SymbolTable symbols() {
        return symbols;
    }

    public List<PublicKey> publicKeys() {
        return publicKeys;
    }

    public void setExternalKey(PublicKey externalKey) {
        this.externalKey = Option.some(externalKey);
    }

    /**
     * pretty printing for a block
     *
     * @param symbolTable
     * @return
     */
    public String print(SymbolTable symbolTable) {
        StringBuilder s = new StringBuilder();

        SymbolTable localSymbols;
        if(this.externalKey.isDefined()) {
            localSymbols = new SymbolTable(this.symbols);
            for(PublicKey pk: symbolTable.getPublicKeys()) {
                localSymbols.insert(pk);
            }
        } else {
            localSymbols = symbolTable;
        }
        s.append("Block");
        s.append(" {\n\t\tsymbols: ");
        s.append(this.symbols.symbols);
        s.append("\n\t\tsymbol public keys: ");
        s.append(this.symbols.getPublicKeys());
        s.append("\n\t\tblock public keys: ");
        s.append(this.publicKeys);
        s.append("\n\t\tcontext: ");
        s.append(this.context);
        if(this.externalKey.isDefined()) {
            s.append("\n\t\texternal key: ");
            s.append(this.externalKey.get().toString());
        }
        s.append("\n\t\tscopes: [");
        for (Scope scope : this.scopes) {
            s.append("\n\t\t\t");
            s.append(symbolTable.formatScope(scope));
        }
        s.append("\n\t\t]\n\t\tfacts: [");
        for (Fact f : this.facts) {
            s.append("\n\t\t\t");
            s.append(localSymbols.formatFact(f));
        }
        s.append("\n\t\t]\n\t\trules: [");
        for (Rule r : this.rules) {
            s.append("\n\t\t\t");
            s.append(localSymbols.formatRule(r));
        }
        s.append("\n\t\t]\n\t\tchecks: [");
        for (Check c : this.checks) {
            s.append("\n\t\t\t");
            s.append(localSymbols.formatCheck(c));
        }
        s.append("\n\t\t]\n\t}");

        return s.toString();
    }

    public String printCode(SymbolTable symbolTable) {
        StringBuilder s = new StringBuilder();

        SymbolTable localSymbols;
        if(this.externalKey.isDefined()) {
            localSymbols = new SymbolTable(this.symbols);
            for(PublicKey pk: symbolTable.getPublicKeys()) {
                localSymbols.insert(pk);
            }
        } else {
            localSymbols = symbolTable;
        }
        /*s.append("Block");
        s.append(" {\n\t\tsymbols: ");
        s.append(this.symbols.symbols);
        s.append("\n\t\tsymbol public keys: ");
        s.append(this.symbols.publicKeys());
        s.append("\n\t\tblock public keys: ");
        s.append(this.publicKeys);
        s.append("\n\t\tcontext: ");
        s.append(this.context);
        if(this.externalKey.isDefined()) {
            s.append("\n\t\texternal key: ");
            s.append(this.externalKey.get().toString());
        }*/
        for (Scope scope : this.scopes) {
            s.append("trusting "+localSymbols.formatScope(scope)+"\n");
        }
        for (Fact f : this.facts) {
            s.append(localSymbols.formatFact(f)+";\n");
        }
        for (Rule r : this.rules) {
            s.append(localSymbols.formatRule(r)+";\n");
        }
        for (Check c : this.checks) {
            s.append(localSymbols.formatCheck(c)+";\n");
        }

        return s.toString();
    }

    /**
     * Serializes a Block to its Protobuf representation
     *
     * @return
     */
    public Schema.Block serialize() {
        Schema.Block.Builder b = Schema.Block.newBuilder();

        for (int i = 0; i < this.symbols.symbols.size(); i++) {
            b.addSymbols(this.symbols.symbols.get(i));
        }

        if (!this.context.isEmpty()) {
            b.setContext(this.context);
        }

        for (int i = 0; i < this.facts.size(); i++) {
            b.addFactsV2(this.facts.get(i).serialize());
        }

        for (int i = 0; i < this.rules.size(); i++) {
            b.addRulesV2(this.rules.get(i).serialize());
        }

        for (int i = 0; i < this.checks.size(); i++) {
            b.addChecksV2(this.checks.get(i).serialize());
        }

        for (Scope scope: this.scopes) {
            b.addScope(scope.serialize());
        }

        for(PublicKey pk: this.publicKeys) {
            b.addPublicKeys(pk.serialize());
        }

        b.setVersion(getSchemaVersion());
        return b.build();
    }

    int getSchemaVersion() {
        boolean containsScopes = !this.scopes.isEmpty();
        boolean containsCheckAll = false;
        boolean containsV4 = false;

        for (Rule r: this.rules) {
            containsScopes |= !r.scopes().isEmpty();
            for(Expression e: r.expressions()) {
                containsV4 |= containsV4Op(e);
            }
        }
        for(Check c: this.checks) {
            containsCheckAll |= c.kind() == Check.Kind.All;

            for (Rule q: c.queries()) {
                containsScopes |= !q.scopes().isEmpty();
                for(Expression e: q.expressions()) {
                    containsV4 |= containsV4Op(e);
                }
            }
        }

        if(this.externalKey.isDefined()) {
            return SerializedBiscuit.MAX_SCHEMA_VERSION;

        }else if(containsScopes || containsCheckAll || containsV4) {
            return 4;
        } else {
            return SerializedBiscuit.MIN_SCHEMA_VERSION;
        }
    }

    boolean containsV4Op(Expression e) {
        for (Op op: e.getOps()) {
            if (op instanceof Op.Binary) {
                Op.BinaryOp o = ((Op.Binary) op).getOp();
                if (o == Op.BinaryOp.BitwiseAnd || o == Op.BinaryOp.BitwiseOr || o == Op.BinaryOp.BitwiseXor || o == Op.BinaryOp.NotEqual) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Deserializes a block from its Protobuf representation
     *
     * @param b
     * @return
     */
    static public Either<Error.FormatError, Block> deserialize(Schema.Block b, Option<PublicKey> externalKey) {
        int version = b.getVersion();
        if (version < SerializedBiscuit.MIN_SCHEMA_VERSION || version > SerializedBiscuit.MAX_SCHEMA_VERSION) {
            return Left(new Error.FormatError.Version(SerializedBiscuit.MIN_SCHEMA_VERSION, SerializedBiscuit.MAX_SCHEMA_VERSION, version));
        }

        SymbolTable symbols = new SymbolTable();
        for (String s : b.getSymbolsList()) {
            symbols.add(s);
        }

        ArrayList<Fact> facts = new ArrayList<>();
        ArrayList<Rule> rules = new ArrayList<>();
        ArrayList<Check> checks = new ArrayList<>();

        for (Schema.FactV2 fact : b.getFactsV2List()) {
            Either<Error.FormatError, Fact> res = Fact.deserializeV2(fact);
            if (res.isLeft()) {
                Error.FormatError e = res.getLeft();
                return Left(e);
            } else {
                facts.add(res.get());
            }
        }


        for (Schema.RuleV2 rule : b.getRulesV2List()) {
            Either<Error.FormatError, Rule> res = Rule.deserializeV2(rule);
            if (res.isLeft()) {
                Error.FormatError e = res.getLeft();
                return Left(e);
            } else {
                rules.add(res.get());
            }
        }


        for (Schema.CheckV2 check : b.getChecksV2List()) {
            Either<Error.FormatError, Check> res = Check.deserializeV2(check);
            if (res.isLeft()) {
                Error.FormatError e = res.getLeft();
                return Left(e);
            } else {
                checks.add(res.get());
            }
        }

        ArrayList<Scope> scopes = new ArrayList<>();
        for (Schema.Scope scope: b.getScopeList()) {
            Either<Error.FormatError, Scope> res = Scope.deserialize(scope);
            if(res.isLeft()) {
                Error.FormatError e = res.getLeft();
                return Left(e);
            } else {
                scopes.add(res.get());
            }
        }

        ArrayList<PublicKey> publicKeys = new ArrayList<>();
        for (Schema.PublicKey pk: b.getPublicKeysList()) {
            try {
                PublicKey key =PublicKey.deserialize(pk);
                publicKeys.add(key);
                symbols.getPublicKeys().add(key);
            } catch(Error.FormatError e) {
                return Left(e);
            }
        }

        SchemaVersion schemaVersion = new SchemaVersion(facts, rules, checks, scopes);
        Either<Error.FormatError, Void> res = schemaVersion.checkCompatibility(version);
        if (res.isLeft()) {
            Error.FormatError e = res.getLeft();
            return Left(e);
        }

        return Right(new Block(symbols, b.getContext(), facts, rules, checks, scopes, publicKeys, externalKey, version));
    }

    /**
     * Deserializes a Block from a byte array
     *
     * @param slice
     * @return
     */
    static public Either<Error.FormatError, Block> fromBytes(byte[] slice, Option<PublicKey> externalKey) {
        try {
            Schema.Block data = Schema.Block.parseFrom(slice);
            return Block.deserialize(data, externalKey);
        } catch (InvalidProtocolBufferException e) {
            return Left(new Error.FormatError.DeserializationError(e.toString()));
        }
    }

    public Either<Error.FormatError, byte[]> toBytes() {
        Schema.Block b = this.serialize();
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            b.writeTo(stream);
            byte[] data = stream.toByteArray();
            return Right(data);
        } catch (IOException e) {
            return Left(new Error.FormatError.SerializationError(e.toString()));
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Block block = (Block) o;

        if (!Objects.equals(symbols, block.symbols)) return false;
        if (!Objects.equals(context, block.context)) return false;
        if (!Objects.equals(facts, block.facts)) return false;
        if (!Objects.equals(rules, block.rules)) return false;
        if (!Objects.equals(checks, block.checks)) return false;
        if (!Objects.equals(scopes, block.scopes)) return false;
        if (!Objects.equals(publicKeys, block.publicKeys)) return false;
        return Objects.equals(externalKey, block.externalKey);
    }

    @Override
    public int hashCode() {
        int result = symbols != null ? symbols.hashCode() : 0;
        result = 31 * result + (context != null ? context.hashCode() : 0);
        result = 31 * result + (facts != null ? facts.hashCode() : 0);
        result = 31 * result + (rules != null ? rules.hashCode() : 0);
        result = 31 * result + (checks != null ? checks.hashCode() : 0);
        result = 31 * result + (scopes != null ? scopes.hashCode() : 0);
        result = 31 * result + (publicKeys != null ? publicKeys.hashCode() : 0);
        result = 31 * result + (externalKey != null ? externalKey.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Block{" +
                "symbols=" + symbols +
                ", context='" + context + '\'' +
                ", facts=" + facts +
                ", rules=" + rules +
                ", checks=" + checks +
                ", scopes=" + scopes +
                ", publicKeys=" + publicKeys +
                ", externalKey=" + externalKey +
                '}';
    }
}

