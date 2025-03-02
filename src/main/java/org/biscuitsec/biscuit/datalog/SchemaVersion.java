package org.biscuitsec.biscuit.datalog;

import org.biscuitsec.biscuit.datalog.expressions.Expression;
import org.biscuitsec.biscuit.datalog.expressions.Op;
import org.biscuitsec.biscuit.error.Error;
import io.vavr.control.Either;
import org.biscuitsec.biscuit.token.format.SerializedBiscuit;

import java.util.List;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

public final class SchemaVersion {
    private boolean containsScopes;
    private boolean containsCheckAll;
    private boolean containsV4;

    public SchemaVersion(List<Fact> facts, List<Rule> rules, List<Check> checks, List<Scope> scopes) {
        containsScopes = !scopes.isEmpty();

        if (!containsScopes) {
            for (Rule r : rules) {
                if (!r.scopes().isEmpty()) {
                    containsScopes = true;
                    break;
                }
            }
        }
        if (!containsScopes) {
            for (Check check : checks) {
                for (Rule query : check.queries()) {
                    if (!query.scopes().isEmpty()) {
                        containsScopes = true;
                        break;
                    }
                }
            }
        }

        containsCheckAll = false;
        for (Check check : checks) {
            if (check.kind() == Check.Kind.All) {
                containsCheckAll = true;
                break;
            }
        }

        containsV4 = false;
        for (Check check : checks) {
            for (Rule query : check.queries()) {
                if (containsV4Ops(query.expressions())) {
                    containsV4 = true;
                    break;
                }
            }
        }
    }

    public int version() {
        if (containsScopes || containsV4 || containsCheckAll) {
            return 4;
        } else {
            return SerializedBiscuit.MIN_SCHEMA_VERSION;
        }
    }

    public Either<Error.FormatError, Void> checkCompatibility(int version) {
        if (version < 4) {
            if (containsScopes) {
                return Left(new Error.FormatError.DeserializationError("v3 blocks must not have scopes"));
            }
            if (containsV4) {
                return Left(new Error.FormatError.DeserializationError("v3 blocks must not have v4 operators (bitwise operators or !="));
            }
            if (containsCheckAll) {
                return Left(new Error.FormatError.DeserializationError("v3 blocks must not use check all"));
            }
        }

        return Right(null);
    }

    public static boolean containsV4Ops(List<Expression> expressions) {
        for (Expression e : expressions) {
            for (Op op : e.getOps()) {
                if (op instanceof Op.Binary) {
                    Op.Binary b = (Op.Binary) op;
                    switch (b.getOp()) {
                        case BitwiseAnd:
                        case BitwiseOr:
                        case BitwiseXor:
                        case NotEqual:
                            return true;
                        default:

                    }
                }
            }
        }
        return false;
    }

}
