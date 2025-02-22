package org.biscuitsec.biscuit.datalog;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.error.Error;
import io.vavr.control.Either;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static biscuit.format.schema.Schema.CheckV2.Kind.All;
import static io.vavr.API.Left;
import static io.vavr.API.Right;

public final class Check {
    public enum Kind {
        One,
        All
    }

    private final Kind kind;

    private final List<Rule> queries;

    public Check(Kind kind, List<Rule> queries) {
        this.kind = kind;
        this.queries = queries;
    }

    public Kind kind() {
        return kind;
    }

    public List<Rule> queries() {
        return queries;
    }

    public Schema.CheckV2 serialize() {
        Schema.CheckV2.Builder b = Schema.CheckV2.newBuilder();

        // do not set the kind to One to keep compatibility with older library versions
        switch (this.kind) {
            case All:
                b.setKind(All);
                break;
        }

        for(int i = 0; i < this.queries.size(); i++) {
            b.addQueries(this.queries.get(i).serialize());
        }

        return b.build();
    }

    static public Either<Error.FormatError, Check> deserializeV2(Schema.CheckV2 check) {
        ArrayList<Rule> queries = new ArrayList<>();

        Kind kind;
        switch (check.getKind()) {
            case One:
                kind = Kind.One;
                break;
            case All:
                kind = Kind.All;
                break;
            default:
                kind = Kind.One;
                break;
        }

        for (Schema.RuleV2 query: check.getQueriesList()) {
            Either<Error.FormatError, Rule> res = Rule.deserializeV2(query);
            if(res.isLeft()) {
                Error.FormatError e = res.getLeft();
                return Left(e);
            } else {
                queries.add(res.get());
            }
        }

        return Right(new Check(kind, queries));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Check check = (Check) o;

        if (kind != check.kind) return false;
        return Objects.equals(queries, check.queries);
    }

    @Override
    public int hashCode() {
        int result = kind != null ? kind.hashCode() : 0;
        result = 31 * result + (queries != null ? queries.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Check{" +
                "kind=" + kind +
                ", queries=" + queries +
                '}';
    }
}
