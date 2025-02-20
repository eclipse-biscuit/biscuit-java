package org.biscuitsec.biscuit.token.builder;

import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.error.FailedCheck;
import io.vavr.control.Either;
import io.vavr.control.Option;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Rule implements Cloneable {
    Predicate head;
    List<Predicate> body;
    List<Expression> expressions;
    Option<Map<String, Option<Term>>> variables;
    List<Scope> scopes;

    public Rule(Predicate head, List<Predicate> body, List<Expression> expressions, List<Scope> scopes) {
        Map<String, Option<Term>> variables = new HashMap<>();
        this.head = head;
        this.body = body;
        this.expressions = expressions;
        this.scopes = scopes;
        for (Term t : head.terms) {
            if (t instanceof Term.Variable) {
                variables.put(((Term.Variable) t).value, Option.none());
            }
        }
        for (Predicate p : body) {
            for (Term t : p.terms) {
                if (t instanceof Term.Variable) {
                    variables.put(((Term.Variable) t).value, Option.none());
                }
            }
        }
        for (Expression e : expressions) {
            if (e instanceof Expression.Value) {
                Expression.Value ev = (Expression.Value) e;
                if (ev.value instanceof Term.Variable)
                    variables.put(((Term.Variable) ev.value).value, Option.none());
            }
        }
        this.variables = Option.some(variables);
    }

    @Override
    public Rule clone() {
        Predicate head = this.head.clone();
        List<Predicate> body = new ArrayList<>();
        body.addAll(this.body);
        List<Expression> expressions = new ArrayList<>();
        expressions.addAll(this.expressions);
        List<Scope> scopes = new ArrayList<>();
        scopes.addAll(this.scopes);
        return new Rule(head, body, expressions, scopes);
    }

    public void set(String name, Term term) throws Error.Language {
        if (this.variables.isDefined()) {
            Option<Option<Term>> t = Option.of(this.variables.get().get(name));
            if (t.isDefined()) {
                this.variables.get().put(name, Option.some(term));
            } else {
                throw new Error.Language(new FailedCheck.LanguageError.UnknownVariable("name"));
            }
        } else {
            throw new Error.Language(new FailedCheck.LanguageError.UnknownVariable("name"));
        }
    }

    public void apply_variables() {
        this.variables.forEach(
                _variables -> {
                    this.head.terms = this.head.terms.stream().flatMap(t -> {
                        if (t instanceof Term.Variable) {
                            Option<Term> term = _variables.getOrDefault(((Term.Variable) t).value, Option.none());
                            return term.map(_t -> Stream.of(_t)).getOrElse(Stream.of(t));
                        } else return Stream.of(t);
                    }).collect(Collectors.toList());
                    for (Predicate p : this.body) {
                        p.terms = p.terms.stream().flatMap(t -> {
                            if (t instanceof Term.Variable) {
                                Option<Term> term = _variables.getOrDefault(((Term.Variable) t).value, Option.none());
                                return term.map(_t -> Stream.of(_t)).getOrElse(Stream.of(t));
                            } else return Stream.of(t);
                        }).collect(Collectors.toList());
                    }
                    this.expressions = this.expressions.stream().flatMap(
                            e -> {
                                if (e instanceof Expression.Value) {
                                    Expression.Value ev = (Expression.Value) e;
                                    if (ev.value instanceof Term.Variable) {
                                        Option<Term> t = _variables.getOrDefault(((Term.Variable) ev.value).value, Option.none());
                                        if (t.isDefined()) {
                                            return Stream.of(new Expression.Value(t.get()));
                                        }
                                    }
                                }
                                return Stream.of(e);
                            }).collect(Collectors.toList());
                });
    }

    public Either<String, Rule> validate_variables() {
        Set<String> freeVariables = this.head.terms.stream().flatMap(t -> {
            if (t instanceof Term.Variable) {
                return Stream.of(((Term.Variable) t).value);
            } else return Stream.empty();
        }).collect(Collectors.toSet());

        for(Expression e: this.expressions) {
            e.gatherVariables(freeVariables);
        }
        if (freeVariables.isEmpty()) {
            return Either.right(this);
        }

        for (Predicate p : this.body) {
            for (Term term : p.terms) {
                if (term instanceof Term.Variable) {
                    freeVariables.remove(((Term.Variable) term).value);
                    if (freeVariables.isEmpty()) {
                        return Either.right(this);
                    }
                }
            }
        }

        return Either.left("rule head or expressions contains variables that are not used in predicates of the rule's body: " + freeVariables.toString());
    }

    public org.biscuitsec.biscuit.datalog.Rule convert(SymbolTable symbols) {
        Rule r = this.clone();
        r.apply_variables();
        org.biscuitsec.biscuit.datalog.Predicate head = r.head.convert(symbols);
        ArrayList<org.biscuitsec.biscuit.datalog.Predicate> body = new ArrayList<>();
        ArrayList<org.biscuitsec.biscuit.datalog.expressions.Expression> expressions = new ArrayList<>();
        ArrayList<org.biscuitsec.biscuit.datalog.Scope> scopes = new ArrayList<>();


        for (Predicate p : r.body) {
            body.add(p.convert(symbols));
        }

        for (Expression e : r.expressions) {
            expressions.add(e.convert(symbols));
        }

        for (Scope s : r.scopes) {
            scopes.add(s.convert(symbols));
        }

        return new org.biscuitsec.biscuit.datalog.Rule(head, body, expressions, scopes);
    }

    public static Rule convert_from(org.biscuitsec.biscuit.datalog.Rule r, SymbolTable symbols) {
        Predicate head = Predicate.convert_from(r.head(), symbols);

        ArrayList<Predicate> body = new ArrayList<>();
        ArrayList<Expression> expressions = new ArrayList<>();
        ArrayList<Scope> scopes = new ArrayList<>();


        for (org.biscuitsec.biscuit.datalog.Predicate p : r.body()) {
            body.add(Predicate.convert_from(p, symbols));
        }

        for (org.biscuitsec.biscuit.datalog.expressions.Expression e : r.expressions()) {
            expressions.add(Expression.convert_from(e, symbols));
        }

        for (org.biscuitsec.biscuit.datalog.Scope s : r.scopes()) {
            scopes.add(Scope.convert_from(s, symbols));
        }

        return new Rule(head, body, expressions, scopes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Rule rule = (Rule) o;

        if (head != null ? !head.equals(rule.head) : rule.head != null) return false;
        if (body != null ? !body.equals(rule.body) : rule.body != null) return false;
        if (scopes != null ? !scopes.equals(rule.scopes) : rule.scopes != null) return false;
        return expressions != null ? expressions.equals(rule.expressions) : rule.expressions == null;
    }

    @Override
    public int hashCode() {
        int result = head != null ? head.hashCode() : 0;
        result = 31 * result + (body != null ? body.hashCode() : 0);
        result = 31 * result + (expressions != null ? expressions.hashCode() : 0);
        result = 31 * result + (scopes != null ? scopes.hashCode() : 0);
        return result;
    }

    public String bodyToString() {
        Rule r = this.clone();
        r.apply_variables();
        String res = "";

        if(!r.body.isEmpty()) {
            final List<String> b = r.body.stream().map((pred) -> pred.toString()).collect(Collectors.toList());
             res += String.join(", ", b);
        }

        if (!r.expressions.isEmpty()) {
            if(!r.body.isEmpty()) {
                res += ", ";
            }
            final List<String> e = r.expressions.stream().map((expression) -> expression.toString()).collect(Collectors.toList());
            res += String.join(", ", e);
        }

        if(!r.scopes.isEmpty()) {
            if(!r.body.isEmpty() || !r.expressions.isEmpty()) {
                res += " ";
            }
            final List<String> e = r.scopes.stream().map((scope) -> scope.toString()).collect(Collectors.toList());
            res += "trusting " + String.join(", ", e);
        }

        return res;
    }
    @Override
    public String toString() {
        Rule r = this.clone();
        r.apply_variables();
        return r.head.toString() + " <- " + bodyToString();
    }
}
