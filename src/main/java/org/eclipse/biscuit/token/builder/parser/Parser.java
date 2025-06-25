/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token.builder.parser;

import biscuit.format.schema.Schema;
import io.vavr.Tuple2;
import io.vavr.Tuple4;
import io.vavr.Tuple5;
import io.vavr.collection.Stream;
import io.vavr.control.Either;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.Policy;
import org.eclipse.biscuit.token.builder.Block;
import org.eclipse.biscuit.token.builder.Check;
import org.eclipse.biscuit.token.builder.Expression;
import org.eclipse.biscuit.token.builder.Fact;
import org.eclipse.biscuit.token.builder.Predicate;
import org.eclipse.biscuit.token.builder.Rule;
import org.eclipse.biscuit.token.builder.Scope;
import org.eclipse.biscuit.token.builder.Term;
import org.eclipse.biscuit.token.builder.Utils;

public final class Parser {
  private Parser() {}

  /**
   * Takes a datalog string with <code>\n</code> as datalog line separator. It tries to parse each
   * line using fact, rule, check and scope sequentially.
   *
   * <p>If one succeeds it returns Right(Block) else it returns a Map[lineNumber, List[Error]]
   *
   * @param s datalog string to parse
   * @return Either<Map<Integer, List<Error>>, Tuple5<List<Fact>, List<Rule>, List<Check>,
   *     List<Scope>, List<Policy>>>
   */
  public static Either<
          Map<Integer, List<Error>>,
          Tuple5<List<Fact>, List<Rule>, List<Check>, List<Scope>, List<Policy>>>
      datalogComponents(String s) {
    List<Fact> facts = new ArrayList<>();
    List<Rule> rules = new ArrayList<>();
    List<Check> checks = new ArrayList<>();
    List<Scope> scopes = new ArrayList<>();
    List<Policy> policies = new ArrayList<>();

    if (s.isEmpty()) {
      return Either.right(new Tuple5<>(facts, rules, checks, scopes, policies));
    }

    Map<Integer, List<Error>> errors = new HashMap<>();

    s = removeCommentsAndWhitespaces(s);
    String[] codeLines = s.split(";");

    Stream.of(codeLines)
        .zipWithIndex()
        .forEach(
            indexedLine -> {
              String code = indexedLine._1.strip();

              if (!code.isEmpty()) {
                List<Error> lineErrors = new ArrayList<>();

                boolean parsed;
                var ruleResult = rule(code);
                if (ruleResult.isOk()) {
                  rules.add(ruleResult.getOk()._2);
                  parsed = true;
                } else {
                  lineErrors.add(ruleResult.getErr());
                  parsed = false;
                }

                if (!parsed) {
                  var factResult = fact(code);
                  if (factResult.isOk()) {
                    facts.add(factResult.getOk()._2);
                    parsed = true;
                  } else {
                    lineErrors.add(factResult.getErr());
                    parsed = false;
                  }
                }

                if (!parsed) {
                  var checkResult = check(code);
                  if (checkResult.isOk()) {
                    checks.add(checkResult.getOk()._2);
                    parsed = true;
                  } else {
                    lineErrors.add(checkResult.getErr());
                    parsed = false;
                  }
                }

                if (!parsed) {
                  var scopeResult = scope(code);
                  if (scopeResult.isOk()) {
                    scopes.add(scopeResult.getOk()._2);
                    parsed = true;
                  } else {
                    lineErrors.add(scopeResult.getErr());
                    parsed = false;
                  }
                }

                if (!parsed) {
                  var policyResult = policy(code);
                  if (policyResult.isOk()) {
                    policies.add(policyResult.getOk()._2);
                    parsed = true;
                  } else {
                    lineErrors.add(policyResult.getErr());
                    parsed = false;
                  }
                }

                if (!parsed) {
                  lineErrors.forEach(System.out::println);
                  int lineNumber = indexedLine._2;
                  errors.put(lineNumber, lineErrors);
                }
              }
            });

    if (!errors.isEmpty()) {
      return Either.left(errors);
    }

    return Either.right(new Tuple5<>(facts, rules, checks, scopes, policies));
  }

  /**
   * Takes a datalog string with <code>\n</code> as datalog line separator. It tries to parse each
   * line using fact, rule, check and scope sequentially.
   *
   * <p>If one succeeds it returns Right(Block) else it returns a Map[lineNumber, List[Error]]
   *
   * @param index block index
   * @param s datalog string to parse
   * @return Either<Map<Integer, List<Error>>, Block>
   */
  public static Either<Map<Integer, List<Error>>, Block> datalog(long index, String s) {
    Block blockBuilder = new Block();

    Either<
            Map<Integer, List<Error>>,
            Tuple5<List<Fact>, List<Rule>, List<Check>, List<Scope>, List<Policy>>>
        result = datalogComponents(s);

    if (result.isLeft()) {
      return Either.left(result.getLeft());
    }

    Tuple5<List<Fact>, List<Rule>, List<Check>, List<Scope>, List<Policy>> components =
        result.get();

    if (!components._5.isEmpty()) {
      return Either.left(
          Map.of(
              -1, // we don't have a line number for policies
              List.of(
                  new Error(
                      s,
                      "Policies must be empty but found " + components._5.size() + " policies"))));
    }

    components._1.forEach(blockBuilder::addFact);
    components._2.forEach(blockBuilder::addRule);
    components._3.forEach(blockBuilder::addCheck);
    components._4.forEach(blockBuilder::addScope);

    return Either.right(blockBuilder);
  }

  public static Result<Tuple2<String, Fact>, Error> fact(String s) {
    var res = factPredicate(s);
    if (res.isErr()) {
      return Result.err(res.getErr());
    } else {
      Tuple2<String, Predicate> t = res.getOk();

      if (!t._1.isEmpty()) {
        return Result.err(new Error(s, "the string was not entirely parsed, remaining: " + t._1));
      }

      return Result.ok(new Tuple2<>(t._1, new Fact(t._2)));
    }
  }

  public static Result<Tuple2<String, Rule>, Error> rule(String s) {
    var res0 = predicate(s);
    if (res0.isErr()) {
      return Result.err(res0.getErr());
    }

    Tuple2<String, Predicate> t0 = res0.getOk();
    s = t0._1;

    s = space(s);
    if (s.length() < 2 || s.charAt(0) != '<' || s.charAt(1) != '-') {
      return Result.err(new Error(s, "rule arrow not found"));
    }

    List<Predicate> predicates = new ArrayList<Predicate>();
    s = s.substring(2);

    var bodyRes = ruleBody(s);
    if (bodyRes.isErr()) {
      return Result.err(bodyRes.getErr());
    }

    Tuple4<String, List<Predicate>, List<Expression>, List<Scope>> body = bodyRes.getOk();

    if (!body._1.isEmpty()) {
      return Result.err(new Error(s, "the string was not entirely parsed, remaining: " + body._1));
    }

    Predicate head = t0._2;
    Rule rule = new Rule(head, body._2, body._3, body._4);
    Either<String, Rule> valid = rule.validateVariables();
    if (valid.isLeft()) {
      return Result.err(new Error(s, valid.getLeft()));
    }

    return Result.ok(new Tuple2<>(body._1, rule));
  }

  public static Result<Tuple2<String, Check>, Error> check(String s) {
    org.eclipse.biscuit.datalog.Check.Kind kind;

    if (s.startsWith("check if")) {
      kind = org.eclipse.biscuit.datalog.Check.Kind.ONE;
      s = s.substring("check if".length());
    } else if (s.startsWith("check all")) {
      kind = org.eclipse.biscuit.datalog.Check.Kind.ALL;
      s = s.substring("check all".length());
    } else {
      return Result.err(new Error(s, "missing check prefix"));
    }

    var bodyRes = checkBody(s);
    if (bodyRes.isErr()) {
      return Result.err(bodyRes.getErr());
    }

    Tuple2<String, List<Rule>> t = bodyRes.getOk();

    if (!t._1.isEmpty()) {
      return Result.err(new Error(s, "the string was not entirely parsed, remaining: " + t._1));
    }

    return Result.ok(new Tuple2<>(t._1, new Check(kind, t._2)));
  }

  public static Result<Tuple2<String, Policy>, Error> policy(String s) {
    Policy.Kind p = Policy.Kind.ALLOW;

    String allow = "allow if";
    String deny = "deny if";
    if (s.startsWith(allow)) {
      s = s.substring(allow.length());
    } else if (s.startsWith(deny)) {
      p = Policy.Kind.DENY;
      s = s.substring(deny.length());
    } else {
      return Result.err(new Error(s, "missing policy prefix"));
    }

    List<Rule> queries = new ArrayList<>();
    var bodyRes = checkBody(s);
    if (bodyRes.isErr()) {
      return Result.err(bodyRes.getErr());
    }

    Tuple2<String, List<Rule>> t = bodyRes.getOk();

    if (!t._1.isEmpty()) {
      return Result.err(new Error(s, "the string was not entirely parsed, remaining: " + t._1));
    }

    return Result.ok(new Tuple2<>(t._1, new Policy(t._2, p)));
  }

  public static Result<Tuple2<String, List<Rule>>, Error> checkBody(String s) {
    List<Rule> queries = new ArrayList<>();
    var bodyRes = ruleBody(s);
    if (bodyRes.isErr()) {
      return Result.err(bodyRes.getErr());
    }

    Tuple4<String, List<Predicate>, List<Expression>, List<Scope>> body = bodyRes.getOk();

    s = body._1;
    // FIXME: parse scopes
    queries.add(new Rule(new Predicate("query", new ArrayList<>()), body._2, body._3, body._4));

    int i = 0;
    while (true) {
      if (s.isEmpty()) {
        break;
      }

      s = space(s);

      if (!s.startsWith("or")) {
        break;
      }
      s = s.substring(2);

      var bodyRes2 = ruleBody(s);
      if (bodyRes2.isErr()) {
        return Result.err(bodyRes2.getErr());
      }

      Tuple4<String, List<Predicate>, List<Expression>, List<Scope>> body2 = bodyRes2.getOk();

      s = body2._1;
      queries.add(
          new Rule(new Predicate("query", new ArrayList<>()), body2._2, body2._3, body2._4));
    }

    return Result.ok(new Tuple2<>(s, queries));
  }

  public static Result<Tuple4<String, List<Predicate>, List<Expression>, List<Scope>>, Error>
      ruleBody(String s) {
    List<Predicate> predicates = new ArrayList<Predicate>();
    List<Expression> expressions = new ArrayList<>();

    while (true) {
      s = space(s);

      var res = predicate(s);
      if (res.isOk()) {
        Tuple2<String, Predicate> t = res.getOk();
        s = t._1;
        predicates.add(t._2);
      } else {
        var res2 = expression(s);
        if (res2.isOk()) {
          Tuple2<String, Expression> t2 = res2.getOk();
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

    var res = scopes(s);
    if (res.isErr()) {
      return Result.ok(new Tuple4<>(s, predicates, expressions, new ArrayList<>()));
    } else {
      Tuple2<String, List<Scope>> t = res.getOk();
      return Result.ok(new Tuple4<>(t._1, predicates, expressions, t._2));
    }
  }

  public static Result<Tuple2<String, Predicate>, Error> predicate(String s) {
    Tuple2<String, String> tn =
        takewhile(
            s, (c) -> Character.isAlphabetic(c) || Character.isDigit(c) || c == '_' || c == ':');
    String name = tn._1;
    s = tn._2;

    s = space(s);
    if (s.length() == 0 || s.charAt(0) != '(') {
      return Result.err(new Error(s, "opening parens not found for predicate " + name));
    }
    s = s.substring(1);

    List<Term> terms = new ArrayList<Term>();
    while (true) {

      s = space(s);

      var res = term(s);
      if (res.isErr()) {
        break;
      }

      Tuple2<String, Term> t = res.getOk();
      s = t._1;
      terms.add(t._2);

      s = space(s);

      if (s.isEmpty() || s.charAt(0) != ',') {
        break;
      } else {
        s = s.substring(1);
      }
    }

    s = space(s);
    if (s.isEmpty() || s.charAt(0) != ')') {
      return Result.err(new Error(s, "closing parens not found"));
    }
    String remaining = s.substring(1);

    return Result.ok(new Tuple2<String, Predicate>(remaining, new Predicate(name, terms)));
  }

  public static Result<Tuple2<String, List<Scope>>, Error> scopes(String s) {
    if (!s.startsWith("trusting")) {
      return Result.err(new Error(s, "missing scopes prefix"));
    }
    s = s.substring("trusting".length());
    s = space(s);

    List<Scope> scopes = new ArrayList<Scope>();

    while (true) {
      s = space(s);

      var res = scope(s);
      if (res.isErr()) {
        break;
      }

      Tuple2<String, Scope> t = res.getOk();
      s = t._1;
      scopes.add(t._2);

      s = space(s);

      if (s.isEmpty() || s.charAt(0) != ',') {
        break;
      } else {
        s = s.substring(1);
      }
    }

    return Result.ok(new Tuple2<>(s, scopes));
  }

  public static Result<Tuple2<String, Scope>, Error> scope(String s) {
    if (s.startsWith("authority")) {
      s = s.substring("authority".length());
      return Result.ok(new Tuple2<>(s, Scope.authority()));
    }

    if (s.startsWith("previous")) {
      s = s.substring("previous".length());
      return Result.ok(new Tuple2<>(s, Scope.previous()));
    }

    if (!s.isEmpty() && s.charAt(0) == '{') {
      String remaining = s.substring(1);
      var res = name(remaining);
      if (res.isErr()) {
        return Result.err(new Error(s, "unrecognized parameter"));
      }
      Tuple2<String, String> t = res.getOk();
      if (!s.isEmpty() && s.charAt(0) == '}') {
        return Result.ok(new Tuple2<>(t._1, Scope.parameter(t._2)));
      } else {
        return Result.err(new Error(s, "unrecognized parameter end"));
      }
    }

    var res2 = publicKey(s);
    if (res2.isErr()) {
      return Result.err(new Error(s, "unrecognized public key"));
    }
    Tuple2<String, PublicKey> t = res2.getOk();
    return Result.ok(new Tuple2<>(t._1, Scope.publicKey(t._2)));
  }

  public static Result<Tuple2<String, PublicKey>, Error> publicKey(String s) {
    Schema.PublicKey.Algorithm algorithm;
    if (s.startsWith("ed25519/")) {
      s = s.substring("ed25519/".length());
      algorithm = Schema.PublicKey.Algorithm.Ed25519;
    } else if (s.startsWith("secp256r1/")) {
      s = s.substring("secp256r1/".length());
      algorithm = Schema.PublicKey.Algorithm.SECP256R1;
    } else {
      return Result.err(new Error(s, "unrecognized public key prefix"));
    }

    var t = hex(s);
    PublicKey publicKey;
    try {
      publicKey = PublicKey.load(algorithm, t._2);
    } catch (org.eclipse.biscuit.error.Error.FormatError e) {
      return Result.err(new Error(s, e.getMessage()));
    }
    return Result.ok(new Tuple2<>(t._1, publicKey));
  }

  public static Result<Tuple2<String, Predicate>, Error> factPredicate(String s) {
    Tuple2<String, String> tn =
        takewhile(
            s, (c) -> Character.isAlphabetic(c) || Character.isDigit(c) || c == '_' || c == ':');
    String name = tn._1;
    s = tn._2;

    s = space(s);
    if (s.length() == 0 || s.charAt(0) != '(') {
      return Result.err(new Error(s, "opening parens not found for fact " + name));
    }
    s = s.substring(1);

    List<Term> terms = new ArrayList<Term>();
    while (true) {

      s = space(s);

      var res = factTerm(s);
      if (res.isErr()) {
        break;
      }

      Tuple2<String, Term> t = res.getOk();
      s = t._1;
      terms.add(t._2);

      s = space(s);

      if (s.isEmpty() || s.charAt(0) != ',') {
        break;
      } else {
        s = s.substring(1);
      }
    }

    s = space(s);
    if (s.isEmpty() || s.charAt(0) != ')') {
      return Result.err(new Error(s, "closing parens not found"));
    }
    String remaining = s.substring(1);

    return Result.ok(new Tuple2<String, Predicate>(remaining, new Predicate(name, terms)));
  }

  public static Result<Tuple2<String, String>, Error> name(String s) {
    Tuple2<String, String> t = takewhile(s, (c) -> Character.isAlphabetic(c) || c == '_');
    String name = t._1;
    String remaining = t._2;

    return Result.ok(new Tuple2<String, String>(remaining, name));
  }

  public static Result<Tuple2<String, Term>, Error> term(String s) {
    var res5 = variable(s);
    if (res5.isOk()) {
      Tuple2<String, Term.Variable> t = res5.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res2 = string(s);
    if (res2.isOk()) {
      Tuple2<String, Term.Str> t = res2.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res7 = set(s);
    if (res7.isOk()) {
      Tuple2<String, Term.Set> t = res7.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res6 = bool(s);
    if (res6.isOk()) {
      Tuple2<String, Term.Bool> t = res6.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res4 = date(s);
    if (res4.isOk()) {
      Tuple2<String, Term.Date> t = res4.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res3 = integer(s);
    if (res3.isOk()) {
      Tuple2<String, Term.Integer> t = res3.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res8 = bytes(s);
    if (res8.isOk()) {
      Tuple2<String, Term.Bytes> t = res8.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    return Result.err(new Error(s, "unrecognized value"));
  }

  public static Result<Tuple2<String, Term>, Error> factTerm(String s) {
    if (!s.isEmpty() && s.charAt(0) == '$') {
      return Result.err(new Error(s, "variables are not allowed in facts"));
    }

    var res2 = string(s);
    if (res2.isOk()) {
      Tuple2<String, Term.Str> t = res2.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res7 = set(s);
    if (res7.isOk()) {
      Tuple2<String, Term.Set> t = res7.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res6 = bool(s);
    if (res6.isOk()) {
      Tuple2<String, Term.Bool> t = res6.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res4 = date(s);
    if (res4.isOk()) {
      Tuple2<String, Term.Date> t = res4.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res3 = integer(s);
    if (res3.isOk()) {
      Tuple2<String, Term.Integer> t = res3.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    var res8 = bytes(s);
    if (res8.isOk()) {
      Tuple2<String, Term.Bytes> t = res8.getOk();
      return Result.ok(new Tuple2<>(t._1, t._2));
    }

    return Result.err(new Error(s, "unrecognized value"));
  }

  public static Result<Tuple2<String, Term.Str>, Error> string(String s) {
    if (s.charAt(0) != '"') {
      return Result.err(new Error(s, "not a string"));
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
      return Result.err(new Error(s, "end of string not found"));
    }

    if (s.charAt(index + 1) != '"') {
      return Result.err(new Error(s, "ending double quote not found"));
    }

    String string = s.substring(1, index + 1);
    String remaining = s.substring(index + 2);

    return Result.ok(new Tuple2<String, Term.Str>(remaining, (Term.Str) Utils.string(string)));
  }

  public static Result<Tuple2<String, Term.Integer>, Error> integer(String s) {
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
      return Result.err(new Error(s, "not an integer"));
    }

    long i = Long.parseLong(s.substring(0, index2));
    String remaining = s.substring(index2);

    return Result.ok(new Tuple2<String, Term.Integer>(remaining, (Term.Integer) Utils.integer(i)));
  }

  public static Result<Tuple2<String, Term.Date>, Error> date(String s) {
    Tuple2<String, String> t = takewhile(s, (c) -> c != ' ' && c != ',' && c != ')' && c != ']');

    try {
      OffsetDateTime d = OffsetDateTime.parse(t._1);
      String remaining = t._2;
      return Result.ok(new Tuple2<String, Term.Date>(remaining, new Term.Date(d.toEpochSecond())));
    } catch (DateTimeParseException e) {
      return Result.err(new Error(s, "not a date"));
    }
  }

  public static Result<Tuple2<String, Term.Variable>, Error> variable(String s) {
    if (s.charAt(0) != '$') {
      return Result.err(new Error(s, "not a variable"));
    }

    Tuple2<String, String> t =
        takewhile(
            s.substring(1), (c) -> Character.isAlphabetic(c) || Character.isDigit(c) || c == '_');

    return Result.ok(new Tuple2<String, Term.Variable>(t._2, (Term.Variable) Utils.var(t._1)));
  }

  public static Result<Tuple2<String, Term.Bool>, Error> bool(String s) {
    boolean b;
    if (s.startsWith("true")) {
      b = true;
      s = s.substring(4);
    } else if (s.startsWith("false")) {
      b = false;
      s = s.substring(5);
    } else {
      return Result.err(new Error(s, "not a boolean"));
    }

    return Result.ok(new Tuple2<>(s, new Term.Bool(b)));
  }

  public static Result<Tuple2<String, Term.Set>, Error> set(String s) {
    if (s.isEmpty() || s.charAt(0) != '[') {
      return Result.err(new Error(s, "not a set"));
    }

    s = s.substring(1);

    HashSet<Term> terms = new HashSet<Term>();
    while (true) {

      s = space(s);

      var res = factTerm(s);
      if (res.isErr()) {
        break;
      }

      Tuple2<String, Term> t = res.getOk();

      if (t._2 instanceof Term.Variable) {
        return Result.err(new Error(s, "sets cannot contain variables"));
      }

      s = t._1;
      terms.add(t._2);

      s = space(s);

      if (s.isEmpty() || s.charAt(0) != ',') {
        break;
      } else {
        s = s.substring(1);
      }
    }

    s = space(s);
    if (s.isEmpty() || s.charAt(0) != ']') {
      return Result.err(new Error(s, "closing square bracket not found"));
    }

    String remaining = s.substring(1);

    return Result.ok(new Tuple2<>(remaining, new Term.Set(terms)));
  }

  public static Result<Tuple2<String, Term.Bytes>, Error> bytes(String s) {
    if (!s.startsWith("hex:")) {
      return Result.err(new Error(s, "not a bytes array"));
    }
    s = s.substring(4);
    Tuple2<String, byte[]> t = hex(s);
    return Result.ok(new Tuple2<>(t._1, new Term.Bytes(t._2)));
  }

  public static Tuple2<String, byte[]> hex(String s) {
    int index = 0;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if ("0123456789ABCDEFabcdef".indexOf(c) == -1) {
        break;
      }

      index += 1;
    }

    String hex = s.substring(0, index);
    byte[] bytes = Utils.hexStringToByteArray(hex);
    s = s.substring(index);
    return new Tuple2<>(s, bytes);
  }

  public static Result<Tuple2<String, Expression>, Error> expression(String s) {
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

  public static Tuple2<String, String> takewhile(String s, Function<Character, Boolean> f) {
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
        Tuple2<String, String> split = takewhile(remaining, c -> !finalRemaining.startsWith("*/"));
        remaining = split._2.length() > 2 ? split._2.substring(2) : ""; // Skip "*/"
      } else if (remaining.startsWith("//")) {
        // Find the end of the single-line comment
        remaining = remaining.substring(2); // Skip "//"
        Tuple2<String, String> split = takewhile(remaining, c -> c != '\n' && c != '\r');
        remaining = split._2;
        if (!remaining.isEmpty()) {
          result.append(remaining.charAt(0)); // Preserve line break
          remaining = remaining.substring(1);
        }
      } else {
        // Take non-comment text until the next comment or end of string
        String finalRemaining = remaining;
        Tuple2<String, String> split =
            takewhile(
                remaining,
                c -> !finalRemaining.startsWith("/*") && !finalRemaining.startsWith("//"));
        result.append(split._1);
        remaining = split._2;
      }
    }

    return result.toString();
  }
}
