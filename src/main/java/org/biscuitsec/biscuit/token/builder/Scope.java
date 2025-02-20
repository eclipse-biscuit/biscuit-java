package org.biscuitsec.biscuit.token.builder;

import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.SymbolTable;

import java.util.Objects;

public final class Scope {
    enum Kind {
        Authority,
        Previous,
        PublicKey,
        Parameter,
    }

    Kind kind;
    PublicKey publicKey;
    String parameter;

    private Scope(Kind kind) {
        this.kind = kind;
        this.publicKey = null;
        this.parameter = "";
    }

    private Scope(Kind kind, PublicKey publicKey) {
        this.kind = kind;
        this.publicKey = publicKey;
        this.parameter = "";
    }

    private Scope(Kind kind, String parameter) {
        this.kind = kind;
        this.publicKey = null;
        this.parameter = parameter;
    }

    public static Scope authority() {
        return new Scope(Kind.Authority);
    }

    public static Scope previous() {
        return new Scope(Kind.Previous);
    }

    public static Scope publicKey(PublicKey publicKey) {
        return new Scope(Kind.PublicKey, publicKey);
    }

    public static Scope parameter(String parameter) {
        return new Scope(Kind.Parameter, parameter);
    }

    public org.biscuitsec.biscuit.datalog.Scope convert(SymbolTable symbols) {
        switch (this.kind) {
            case Authority:
                return org.biscuitsec.biscuit.datalog.Scope.authority();
            case Previous:
                return org.biscuitsec.biscuit.datalog.Scope.previous();
            case Parameter:
                //FIXME
                return null;
            //throw new Exception("Remaining parameter: "+this.parameter);
            case PublicKey:
                return org.biscuitsec.biscuit.datalog.Scope.publicKey(symbols.insert(this.publicKey));
        }
        //FIXME
        return null;
    }

    public static Scope convertFrom(org.biscuitsec.biscuit.datalog.Scope scope, SymbolTable symbols) {
        switch (scope.kind()) {
            case Authority:
                return new Scope(Kind.Authority);
            case Previous:
                return new Scope(Kind.Previous);
            case PublicKey:
                //FIXME error management should bubble up here
                return new Scope(Kind.PublicKey, symbols.getPublicKey((int) scope.publicKey()).get());
        }

        //FIXME error management should bubble up here
        //throw new Exception("panic");
        return null;

    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Scope scope = (Scope) o;

        if (kind != scope.kind) return false;
        if (!Objects.equals(publicKey, scope.publicKey)) return false;
        return Objects.equals(parameter, scope.parameter);
    }

    @Override
    public int hashCode() {
        int result = kind.hashCode();
        result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
        result = 31 * result + (parameter != null ? parameter.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        switch (this.kind) {
            case Authority:
                return "authority";
            case Previous:
                return "previous";
            case Parameter:
                return "{" + this.parameter + "}";
            case PublicKey:
                return this.publicKey.toString();
        }
        return null;
    }
}
