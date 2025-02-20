package org.biscuitsec.biscuit.token.builder.parser;

import biscuit.format.schema.Schema;
import io.vavr.collection.Stream;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.token.Policy;
import io.vavr.Tuple2;
import io.vavr.Tuple4;
import io.vavr.control.Either;
import org.biscuitsec.biscuit.token.builder.Block;
import org.biscuitsec.biscuit.token.builder.Check;
import org.biscuitsec.biscuit.token.builder.Expression;
import org.biscuitsec.biscuit.token.builder.Fact;
import org.biscuitsec.biscuit.token.builder.Predicate;
import org.biscuitsec.biscuit.token.builder.Rule;
import org.biscuitsec.biscuit.token.builder.Scope;
import org.biscuitsec.biscuit.token.builder.Term;
import org.biscuitsec.biscuit.token.builder.Utils;


import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public final class Parser {
    private Parser() {}

    /**
     * Takes a datalog string with <code>\n</code> as datalog line separator. It tries to parse
     * each line using fact, rule, check and scope sequentially.
     *
     * If one succeeds it returns Right(Block)
     * else it returns a Map[lineNumber, List[Error]]
     *
     * @param index block index
     * @param s datalog string to parse
     * @return Either<Map<Integer, List<Error>>, Block>
     */
    public static Either<Map<Integer, List<Error>>, Block> datalog(long index, String s) {
        Block blockBuilder = new Block();

        // empty block code
        if (s.isEmpty()) {
            return Either.right(blockBuilder);
        }

        Map<Integer, List<Error>> errors = new HashMap<>();

        s = removeCommentsAndWhitespaces(s);
        String[] codeLines = s.split(";");

        Stream.of(codeLines)
                .zipWithIndex()
                .forEach(indexedLine -> {
           String code = indexedLine._1.strip();

           if (!code.isEmpty()) {
               int lineNumber = indexedLine._2;
               List<Error> lineErrors = new ArrayList<>();

               boolean parsed = false;
               parsed = rule(code).fold(e -> {
                   lineErrors.add(e);
                   return false;
               }, r -> {
                   blockBuilder.addRule(r._2);
                   return true;
               });

               if (!parsed) {
                   parsed = fact(code).fold(e -> {
                       lineErrors.add(e);
                       return false;
                   }, r -> {
                       blockBuilder.addFact(r._2);
                       return true;
                   });
               }

               if (!parsed) {
                   parsed = check(code).fold(e -> {
                       lineErrors.add(e);
                       return false;
                   }, r -> {
                       blockBuilder.addCheck(r._2);
                       return true;
                   });
               }

               if (!parsed) {
                   parsed = scope(code).fold(e -> {
                       lineErrors.add(e);
                       return false;
                   }, r -> {
                       blockBuilder.addScope(r._2);
                       return true;
                   });
               }

               if (!parsed) {
                   lineErrors.forEach(System.out::println);
                   errors.put(lineNumber, lineErrors);
               }
           }
        });

        if (!errors.isEmpty()) {
            return Either.left(errors);
        }

        return Either.right(blockBuilder);
    }

    public static Either<Error, Tuple2<String, Fact>> fact(String s) {
        Either<Error, Tuple2<String, Predicate>> res = factPredicate(s);
        if (res.isLeft()) {
            return Either.left(res.getLeft());
        } else {
            Tuple2<String, Predicate> t = res.get();

            if (!t._1.isEmpty()) {
                return Either.left(new Error(s, "the string was not entirely parsed, remaining: " + t._1));
            }

            return Either.right(new Tuple2<>(t._1, new Fact(t._2)));
        }
    }

    public static Either<Error, Tuple2<String, Rule>> rule(String s) {
        Either<Error, Tuple2<String, Predicate>> res0 = predicate(s);
        if (res0.isLeft()) {
            return Either.left(res0.getLeft());
        }

        Tuple2<String, Predicate> t0 = res0.get();
        s = t0._1;
        Predicate head = t0._2;

        s = space(s);
        if (s.length() < 2 || s.charAt(0) != '<' || s.charAt(1) != '-') {
            return Either.left(new Error(s, "rule arrow not found"));
        }

        List<Predicate> predicates = new ArrayList<Predicate>();
        s = s.substring(2);

        Either<Error, Tuple4<String, List<Predicate>, List<Expression>, List<Scope>>> bodyRes = ruleBody(s);
        if (bodyRes.isLeft()) {
            return Either.left(bodyRes.getLeft());
        }

        Tuple4<String, List<Predicate>, List<Expression>, List<Scope>> body = bodyRes.get();

        if (!body._1.isEmpty()) {
            return Either.left(new Error(s, "the string was not entirely parsed, remaining: " + body._1));
        }

        Rule rule = new Rule(head, body._2, body._3, body._4);
        Either<String, Rule> valid = rule.validateVariables();
        if (valid.isLeft()) {
            return Either.left(new Error(s, valid.getLeft()));
        }

        return Either.right(new Tuple2<>(body._1, rule));
    }

    public static Either<Error, Tuple2<String, Check>> check(String s) {
        org.biscuitsec.biscuit.datalog.Check.Kind kind;

        if (s.startsWith("check if")) {
            kind = org.biscuitsec.biscuit.datalog.Check.Kind.One;
            s = s.substring("check if".length());
        } else if (s.startsWith("check all")) {
            kind = org.biscuitsec.biscuit.datalog.Check.Kind.All;
            s = s.substring("check all".length());
        } else {
            return Either.left(new Error(s, "missing check prefix"));
        }

        List<Rule> queries = new ArrayList<>();
        Either<Error, Tuple2<String, List<Rule>>> bodyRes = checkBody(s);
        if (bodyRes.isLeft()) {
            return Either.left(bodyRes.getLeft());
        }

        Tuple2<String, List<Rule>> t = bodyRes.get();

        if (!t._1.isEmpty()) {
            return Either.left(new Error(s, "the string was not entirely parsed, remaining: " + t._1));
        }

        return Either.right(new Tuple2<>(t._1, new Check(kind, t._2)));
    }

    public static Either<Error, Tuple2<String, Policy>> policy(String s) {
        Policy.Kind p = Policy.Kind.Allow;

        String allow = "allow if";
        String deny = "deny if";
        if (s.startsWith(allow)) {
            s = s.substring(allow.length());
        } else if (s.startsWith(deny)) {
            p = Policy.Kind.Deny;
            s = s.substring(deny.length());
        } else {
            return Either.left(new Error(s, "missing policy prefix"));
        }

        List<Rule> queries = new ArrayList<>();
        Either<Error, Tuple2<String, List<Rule>>> bodyRes = checkBody(s);
        if (bodyRes.isLeft()) {
            return Either.left(bodyRes.getLeft());
        }

        Tuple2<String, List<Rule>> t = bodyRes.get();

        if (!t._1.isEmpty()) {
            return Either.left(new Error(s, "the string was not entirely parsed, remaining: " + t._1));
        }

        return Either.right(new Tuple2<>(t._1, new Policy(t._2, p)));
    }

    public static Either<Error, Tuple2<String, List<Rule>>> checkBody(String s) {
        List<Rule> queries = new ArrayList<>();
        Either<Error, Tuple4<String, List<Predicate>, List<Expression>, List<Scope>>> bodyRes = ruleBody(s);
        if (bodyRes.isLeft()) {
            return Either.left(bodyRes.getLeft());
        }

        Tuple4<String, List<Predicate>, List<Expression>, List<Scope>> body = bodyRes.get();

        s = body._1;
        //FIXME: parse scopes
        queries.add(new Rule(new Predicate("query", new ArrayList<>()), body._2, body._3,  body._4));

        int i = 0;
        while (true) {
            if (s.length() == 0) {
                break;
            }

            s = space(s);

            if (!s.startsWith("or")) {
                break;
            }
            s = s.substring(2);

            Either<Error, Tuple4<String, List<Predicate>, List<Expression>, List<Scope>>> bodyRes2 = ruleBody(s);
            if (bodyRes2.isLeft()) {
                return Either.left(bodyRes2.getLeft());
            }

            Tuple4<String, List<Predicate>, List<Expression>, List<Scope>> body2 = bodyRes2.get();

            s = body2._1;
            queries.add(new Rule(new Predicate("query", new ArrayList<>()), body2._2, body2._3,  body2._4));
        }

        return Either.right(new Tuple2<>(s, queries));
    }

    public static Either<Error, Tuple4<String, List<Predicate>, List<Expression>, List<Scope>>> ruleBody(String s) {
        List<Predicate> predicates = new ArrayList<Predicate>();
        List<Expression> expressions = new ArrayList<>();

        while (true) {
            s = space(s);

            Either<Error, Tuple2<String, Predicate>> res = predicate(s);
            if (res.isRight()) {
                Tuple2<String, Predicate> t = res.get();
                s = t._1;
                predicates.add(t._2);
            } else {
                Either<Error, Tuple2<String, Expression>> res2 = expression(s);
                if (res2.isRight()) {
                    Tuple2<String, Expression> t2 = res2.get();
                    s = t2._1;
                    expressions.add(t2._2);
                } else {
                    break;
                }
            }

            s = space(s);

            if (s.length() == 0 || s.charAt(0) != ',') {
                break;
            } else {
                s = s.substring(1);
            }
        }

        Either<Error, Tuple2<String, List<Scope>>> res = scopes(s);
        if(res.isLeft()) {
            return Either.right(new Tuple4<>(s, predicates, expressions, new ArrayList<>()));
        } else {
            Tuple2<String, List<Scope>> t = res.get();
            return Either.right(new Tuple4<>(t._1, predicates, expressions, t._2));

        }

    }

    public static Either<Error, Tuple2<String, Predicate>> predicate(String s) {
        Tuple2<String, String> tn = takeWhile(s, (c) -> Character.isAlphabetic(c) || Character.isDigit(c) || c == '_' || c == ':');
        String name = tn._1;
        s = tn._2;

        s = space(s);
        if (s.length() == 0 || s.charAt(0) != '(') {
            return Either.left(new Error(s, "opening parens not found for predicate "+name));
        }
        s = s.substring(1);

        List<Term> terms = new ArrayList<Term>();
        while (true) {

            s = space(s);

            Either<Error, Tuple2<String, Term>> res = term(s);
            if (res.isLeft()) {
                break;
            }

            Tuple2<String, Term> t = res.get();
            s = t._1;
            terms.add(t._2);

            s = space(s);

            if (s.length() == 0 || s.charAt(0) != ',') {
                break;
            } else {
                s = s.substring(1);
            }
        }

        s = space(s);
        if (0 == s.length() || s.charAt(0) != ')') {
            return Either.left(new Error(s, "closing parens not found"));
        }
        String remaining = s.substring(1);

        return Either.right(new Tuple2<String, Predicate>(remaining, new Predicate(name, terms)));
    }

    public static Either<Error, Tuple2<String, List<Scope>>> scopes(String s) {
        if (!s.startsWith("trusting")) {
            return Either.left(new Error(s, "missing scopes prefix"));
        }
        s = s.substring("trusting".length());
        s = space(s);

        List<Scope> scopes = new ArrayList<Scope>();

        while (true) {
            s = space(s);

            Either<Error, Tuple2<String, Scope>> res = scope(s);
            if (res.isLeft()) {
                break;
            }

            Tuple2<String, Scope> t = res.get();
            s = t._1;
            scopes.add(t._2);

            s = space(s);

            if (s.length() == 0 || s.charAt(0) != ',') {
                break;
            } else {
                s = s.substring(1);
            }
        }

        return Either.right(new Tuple2<>(s, scopes));
    }

    public static Either<Error, Tuple2<String, Scope>> scope(String s) {
        if (s.startsWith("authority")) {
            s = s.substring("authority".length());
            return Either.right(new Tuple2<>(s, Scope.authority()));
        }

        if (s.startsWith("previous")) {
            s = s.substring("previous".length());
            return Either.right(new Tuple2<>(s, Scope.previous()));
        }

        if (0 < s.length() && s.charAt(0) == '{') {
            String remaining = s.substring(1);
            Either<Error, Tuple2<String, String>> res = name(remaining);
            if (res.isLeft()) {
                return Either.left(new Error(s, "unrecognized parameter"));
            }
            Tuple2<String, String> t = res.get();
            if (0 < s.length() && s.charAt(0) == '}') {
                return Either.right(new Tuple2<>(t._1, Scope.parameter(t._2)));
            } else {
                return Either.left(new Error(s, "unrecognized parameter end"));
            }
        }

        Either<Error, Tuple2<String, PublicKey>> res2 = publicKey(s);
        if (res2.isLeft()) {
            return Either.left(new Error(s, "unrecognized public key"));
        }
        Tuple2<String, PublicKey> t = res2.get();
        return Either.right(new Tuple2<>(t._1, Scope.publicKey(t._2)));
    }

    public static Either<Error, Tuple2<String, PublicKey>> publicKey(String s) {
        if (s.startsWith("ed25519/")) {
            s = s.substring("ed25519/".length());
            Tuple2<String, byte[]> t = hex(s);
            return Either.right(new Tuple2(t._1, new PublicKey(Schema.PublicKey.Algorithm.Ed25519, t._2)));
        } else if (s.startsWith("secp256r1/")) {
            s = s.substring("secp256r1/".length());
            Tuple2<String, byte[]> t = hex(s);
            return Either.right(new Tuple2(t._1, new PublicKey(Schema.PublicKey.Algorithm.SECP256R1, t._2)));
        } else {
            return Either.left(new Error(s, "unrecognized public key prefix"));
        }
    }

    public static Either<Error, Tuple2<String, Predicate>> factPredicate(String s) {
        Tuple2<String, String> tn = takeWhile(s, (c) -> Character.isAlphabetic(c) || Character.isDigit(c) || c == '_' || c == ':');
        String name = tn._1;
        s = tn._2;

        s = space(s);
        if (s.length() == 0 || s.charAt(0) != '(') {
            return Either.left(new Error(s, "opening parens not found for fact "+name));
        }
        s = s.substring(1);

        List<Term> terms = new ArrayList<Term>();
        while (true) {

            s = space(s);

            Either<Error, Tuple2<String, Term>> res = factTerm(s);
            if (res.isLeft()) {
                break;
            }

            Tuple2<String, Term> t = res.get();
            s = t._1;
            terms.add(t._2);

            s = space(s);

            if (s.length() == 0 || s.charAt(0) != ',') {
                break;
            } else {
                s = s.substring(1);
            }
        }

        s = space(s);
        if (0 == s.length() || s.charAt(0) != ')') {
            return Either.left(new Error(s, "closing parens not found"));
        }
        String remaining = s.substring(1);

        return Either.right(new Tuple2<String, Predicate>(remaining, new Predicate(name, terms)));
    }

    public static Either<Error, Tuple2<String, String>> name(String s) {
        Tuple2<String, String> t = takeWhile(s, (c) -> Character.isAlphabetic(c) || c == '_');
        String name = t._1;
        String remaining = t._2;

        return Either.right(new Tuple2<String, String>(remaining, name));
    }

    public static Either<Error, Tuple2<String, Term>> term(String s) {

        Either<Error, Tuple2<String, Term.Variable>> res5 = variable(s);
        if (res5.isRight()) {
            Tuple2<String, Term.Variable> t = res5.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Str>> res2 = string(s);
        if (res2.isRight()) {
            Tuple2<String, Term.Str> t = res2.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Set>> res7 = set(s);
        if (res7.isRight()) {
            Tuple2<String, Term.Set> t = res7.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Bool>> res6 = bool(s);
        if (res6.isRight()) {
            Tuple2<String, Term.Bool> t = res6.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Date>> res4 = date(s);
        if (res4.isRight()) {
            Tuple2<String, Term.Date> t = res4.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Integer>> res3 = integer(s);
        if (res3.isRight()) {
            Tuple2<String, Term.Integer> t = res3.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Bytes>> res8 = bytes(s);
        if (res8.isRight()) {
            Tuple2<String, Term.Bytes> t = res8.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        return Either.left(new Error(s, "unrecognized value"));
    }

    public static Either<Error, Tuple2<String, Term>> factTerm(String s) {
        if (s.length() > 0 && s.charAt(0) == '$') {
            return Either.left(new Error(s, "variables are not allowed in facts"));
        }

        Either<Error, Tuple2<String, Term.Str>> res2 = string(s);
        if (res2.isRight()) {
            Tuple2<String, Term.Str> t = res2.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Set>> res7 = set(s);
        if (res7.isRight()) {
            Tuple2<String, Term.Set> t = res7.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Bool>> res6 = bool(s);
        if (res6.isRight()) {
            Tuple2<String, Term.Bool> t = res6.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Date>> res4 = date(s);
        if (res4.isRight()) {
            Tuple2<String, Term.Date> t = res4.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Integer>> res3 = integer(s);
        if (res3.isRight()) {
            Tuple2<String, Term.Integer> t = res3.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        Either<Error, Tuple2<String, Term.Bytes>> res8 = bytes(s);
        if (res8.isRight()) {
            Tuple2<String, Term.Bytes> t = res8.get();
            return Either.right(new Tuple2<>(t._1, t._2));
        }

        return Either.left(new Error(s, "unrecognized value"));
    }

    public static Either<Error, Tuple2<String, Term.Str>> string(String s) {
        if (s.charAt(0) != '"') {
            return Either.left(new Error(s, "not a string"));
        }

        int index = s.length();
        for (int i = 1; i < s.length(); i++) {
            char c = s.charAt(i);

            if (c == '\\' && s.charAt(i + 1) == '"') {
                i += 1;
                continue;
            }

            if (c == '"') {
                index = i - 1;
                break;
            }
        }

        if (index == s.length()) {
            return Either.left(new Error(s, "end of string not found"));
        }

        if (s.charAt(index + 1) != '"') {
            return Either.left(new Error(s, "ending double quote not found"));
        }

        String string = s.substring(1, index + 1);
        String remaining = s.substring(index + 2);

        return Either.right(new Tuple2<String, Term.Str>(remaining, (Term.Str) Utils.string(string)));
    }

    public static Either<Error, Tuple2<String, Term.Integer>> integer(String s) {
        int index = 0;
        if (s.charAt(0) == '-') {
            index += 1;
        }

        int index2 = s.length();
        for (int i = index; i < s.length(); i++) {
            char c = s.charAt(i);

            if (!Character.isDigit(c)) {
                index2 = i;
                break;
            }
        }

        if (index2 == 0) {
            return Either.left(new Error(s, "not an integer"));
        }

        long i = Long.parseLong(s.substring(0, index2));
        String remaining = s.substring(index2);

        return Either.right(new Tuple2<String, Term.Integer>(remaining, (Term.Integer) Utils.integer(i)));
    }

    public static Either<Error, Tuple2<String, Term.Date>> date(String s) {
        Tuple2<String, String> t = takeWhile(s, (c) -> c != ' ' && c != ',' && c != ')' && c != ']');

        try {
            OffsetDateTime d = OffsetDateTime.parse(t._1);
            String remaining = t._2;
            return Either.right(new Tuple2<String, Term.Date>(remaining, new Term.Date(d.toEpochSecond())));
        } catch (DateTimeParseException e) {
            return Either.left(new Error(s, "not a date"));

        }
    }

    public static Either<Error, Tuple2<String, Term.Variable>> variable(String s) {
        if (s.charAt(0) != '$') {
            return Either.left(new Error(s, "not a variable"));
        }

        Tuple2<String, String> t = takeWhile(s.substring(1), (c) -> Character.isAlphabetic(c) || Character.isDigit(c) || c == '_');

        return Either.right(new Tuple2<String, Term.Variable>(t._2, (Term.Variable) Utils.var(t._1)));
    }

    public static Either<Error, Tuple2<String, Term.Bool>> bool(String s) {
        boolean b;
        if (s.startsWith("true")) {
            b = true;
            s = s.substring(4);
        } else if (s.startsWith("false")) {
            b = false;
            s = s.substring(5);
        } else {
            return Either.left(new Error(s, "not a boolean"));
        }

        return Either.right(new Tuple2<>(s, new Term.Bool(b)));
    }

    public static Either<Error, Tuple2<String, Term.Set>> set(String s) {
        if (s.length() == 0 || s.charAt(0) != '[') {
            return Either.left(new Error(s, "not a set"));
        }

        s = s.substring(1);

        HashSet<Term> terms = new HashSet<Term>();
        while (true) {

            s = space(s);

            Either<Error, Tuple2<String, Term>> res = factTerm(s);
            if (res.isLeft()) {
                break;
            }

            Tuple2<String, Term> t = res.get();

            if (t._2 instanceof Term.Variable) {
                return Either.left(new Error(s, "sets cannot contain variables"));
            }

            s = t._1;
            terms.add(t._2);

            s = space(s);

            if (s.length() == 0 || s.charAt(0) != ',') {
                break;
            } else {
                s = s.substring(1);
            }
        }

        s = space(s);
        if (0 == s.length() || s.charAt(0) != ']') {
            return Either.left(new Error(s, "closing square bracket not found"));
        }

        String remaining = s.substring(1);

        return Either.right(new Tuple2<>(remaining, new Term.Set(terms)));
    }

    public static Either<Error, Tuple2<String, Term.Bytes>> bytes(String s) {
        if (!s.startsWith("hex:")) {
            return Either.left(new Error(s, "not a bytes array"));
        }
        s = s.substring(4);
        Tuple2<String, byte[]> t = hex(s);
        return Either.right(new Tuple2<>(t._1, new Term.Bytes(t._2)));
    }

    public static Tuple2<String, byte[]> hex(String s) {
        int index = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if("0123456789ABCDEFabcdef".indexOf(c) == -1) {
                break;
            }

            index += 1;
        }

        String hex =  s.substring(0, index);
        byte[] bytes = Utils.hexStringToByteArray(hex);
        s = s.substring(index);
        return new Tuple2<>(s,bytes);

    }

    public static Either<Error, Tuple2<String, Expression>> expression(String s) {
        return ExpressionParser.parse(s);
    }

    public static String space(String s) {
        int index = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                break;
            }
            index += 1;
        }

        return s.substring(index);
    }

    public static Tuple2<String, String> takeWhile(String s, Function<Character, Boolean> f) {
        int index = s.length();
        for (int i = 0; i < s.length(); i++) {
            Character c = s.charAt(i);

            if (!f.apply(c)) {
                index = i;
                break;
            }
        }

        return new Tuple2<>(s.substring(0, index), s.substring(index));
    }

    public static String removeCommentsAndWhitespaces(String s) {
        s = removeComments(s);
        s = s.replace("\n", "").replace("\\\"", "\"").strip();
        return s;
    }

    public static String removeComments(String str) {
        StringBuilder result = new StringBuilder();
        String remaining = str;

        while (!remaining.isEmpty()) {
            remaining = space(remaining); // Skip leading whitespace
            if (remaining.startsWith("/*")) {
                // Find the end of the multiline comment
                remaining = remaining.substring(2); // Skip "/*"
                String finalRemaining = remaining;
                Tuple2<String, String> split = takeWhile(remaining, c -> !finalRemaining.startsWith("*/"));
                remaining = split._2.length() > 2 ? split._2.substring(2) : ""; // Skip "*/"
            } else if (remaining.startsWith("//")) {
                // Find the end of the single-line comment
                remaining = remaining.substring(2); // Skip "//"
                Tuple2<String, String> split = takeWhile(remaining, c -> c != '\n' && c != '\r');
                remaining = split._2;
                if (!remaining.isEmpty()) {
                    result.append(remaining.charAt(0)); // Preserve line break
                    remaining = remaining.substring(1);
                }
            } else {
                // Take non-comment text until the next comment or end of string
                String finalRemaining = remaining;
                Tuple2<String, String> split = takeWhile(remaining, c -> !finalRemaining.startsWith("/*") && !finalRemaining.startsWith("//"));
                result.append(split._1);
                remaining = split._2;
            }
        }

        return result.toString();
    }
}
