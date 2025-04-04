package org.biscuitsec.biscuit.token;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

import io.vavr.Tuple2;
import io.vavr.Tuple4;
import io.vavr.control.Either;
import io.vavr.control.Option;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.FactSet;
import org.biscuitsec.biscuit.datalog.Origin;
import org.biscuitsec.biscuit.datalog.RuleSet;
import org.biscuitsec.biscuit.datalog.RunLimits;
import org.biscuitsec.biscuit.datalog.Scope;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.datalog.TrustedOrigins;
import org.biscuitsec.biscuit.datalog.World;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.error.FailedCheck;
import org.biscuitsec.biscuit.error.LogicError;
import org.biscuitsec.biscuit.token.builder.Check;
import org.biscuitsec.biscuit.token.builder.Expression;
import org.biscuitsec.biscuit.token.builder.Term;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.biscuitsec.biscuit.token.builder.parser.Parser;

/** Token verification class */
public final class Authorizer {
  private Biscuit token;
  private final List<org.biscuitsec.biscuit.token.builder.Check> checks;
  private final List<Policy> policies;
  private final List<Scope> scopes;
  private final HashMap<Long, List<Long>> publicKeyToBlockId;
  private final World world;
  private final SymbolTable symbolTable;

  private Authorizer(Biscuit token, World w) throws Error.FailedLogic {
    this.token = token;
    this.world = w;
    this.symbolTable = new SymbolTable(this.token.symbolTable);
    this.checks = new ArrayList<>();
    this.policies = new ArrayList<>();
    this.scopes = new ArrayList<>();
    this.publicKeyToBlockId = new HashMap<>();
    updateOnToken();
  }

  /**
   * Creates an empty authorizer
   *
   * <p>used to apply policies when unauthenticated (no token) and to preload an authorizer that is
   * cloned for each new request
   */
  public Authorizer() {
    this.world = new World();
    this.symbolTable = Biscuit.defaultSymbolTable();
    this.checks = new ArrayList<>();
    this.policies = new ArrayList<>();
    this.scopes = new ArrayList<>();
    this.publicKeyToBlockId = new HashMap<>();
  }

  private Authorizer(
      Biscuit token,
      List<org.biscuitsec.biscuit.token.builder.Check> checks,
      List<Policy> policies,
      World world,
      SymbolTable symbolTable) {
    this.token = token;
    this.checks = checks;
    this.policies = policies;
    this.world = world;
    this.symbolTable = symbolTable;
    this.scopes = new ArrayList<>();
    this.publicKeyToBlockId = new HashMap<>();
  }

  /**
   * Creates a authorizer for a token
   *
   * <p>also checks that the token is valid for this root public key
   *
   * @param token
   * @return Authorizer
   */
  public static Authorizer make(Biscuit token) throws Error.FailedLogic {
    return new Authorizer(token, new World());
  }

  public Authorizer clone() {
    return new Authorizer(
        this.token,
        new ArrayList<>(this.checks),
        new ArrayList<>(this.policies),
        new World(this.world),
        new SymbolTable(this.symbolTable));
  }

  public void updateOnToken() throws Error.FailedLogic {
    if (token != null) {
      for (long i = 0; i < token.blocks.size(); i++) {
        Block block = token.blocks.get((int) i);

        if (block.getExternalKey().isDefined()) {
          PublicKey pk = block.getExternalKey().get();
          long newKeyId = this.symbolTable.insert(pk);
          if (!this.publicKeyToBlockId.containsKey(newKeyId)) {
            List<Long> l = new ArrayList<>();
            l.add(i + 1);
            this.publicKeyToBlockId.put(newKeyId, l);
          } else {
            this.publicKeyToBlockId.get(newKeyId).add(i + 1);
          }
        }
      }

      TrustedOrigins authorityTrustedOrigins =
          TrustedOrigins.fromScopes(
              token.authority.getScopes(),
              TrustedOrigins.defaultOrigins(),
              0,
              this.publicKeyToBlockId);

      for (org.biscuitsec.biscuit.datalog.Fact fact : token.authority.getFacts()) {
        org.biscuitsec.biscuit.datalog.Fact convertedFact =
            org.biscuitsec.biscuit.token.builder.Fact.convertFrom(fact, token.symbolTable)
                .convert(this.symbolTable);
        world.addFact(new Origin(0), convertedFact);
      }
      for (org.biscuitsec.biscuit.datalog.Rule rule : token.authority.getRules()) {
        org.biscuitsec.biscuit.token.builder.Rule locRule =
            org.biscuitsec.biscuit.token.builder.Rule.convertFrom(rule, token.symbolTable);
        org.biscuitsec.biscuit.datalog.Rule convertedRule = locRule.convert(this.symbolTable);

        Either<String, org.biscuitsec.biscuit.token.builder.Rule> res = locRule.validateVariables();
        if (res.isLeft()) {
          throw new Error.FailedLogic(
              new LogicError.InvalidBlockRule(0, token.symbolTable.formatRule(convertedRule)));
        }
        TrustedOrigins ruleTrustedOrigins =
            TrustedOrigins.fromScopes(
                convertedRule.scopes(), authorityTrustedOrigins, 0, this.publicKeyToBlockId);
        world.addRule((long) 0, ruleTrustedOrigins, convertedRule);
      }

      for (long i = 0; i < token.blocks.size(); i++) {
        Block block = token.blocks.get((int) i);
        TrustedOrigins blockTrustedOrigins =
            TrustedOrigins.fromScopes(
                block.getScopes(), TrustedOrigins.defaultOrigins(), i + 1, this.publicKeyToBlockId);

        SymbolTable blockSymbolTable = token.symbolTable;

        if (block.getExternalKey().isDefined()) {
          blockSymbolTable = new SymbolTable(block.getSymbolTable(), block.getPublicKeys());
        }

        for (org.biscuitsec.biscuit.datalog.Fact fact : block.getFacts()) {
          org.biscuitsec.biscuit.datalog.Fact convertedFact =
              org.biscuitsec.biscuit.token.builder.Fact.convertFrom(fact, blockSymbolTable)
                  .convert(this.symbolTable);
          world.addFact(new Origin(i + 1), convertedFact);
        }

        for (org.biscuitsec.biscuit.datalog.Rule rule : block.getRules()) {
          org.biscuitsec.biscuit.token.builder.Rule syRole =
              org.biscuitsec.biscuit.token.builder.Rule.convertFrom(rule, blockSymbolTable);
          org.biscuitsec.biscuit.datalog.Rule convertedRule = syRole.convert(this.symbolTable);

          Either<String, org.biscuitsec.biscuit.token.builder.Rule> res =
              syRole.validateVariables();
          if (res.isLeft()) {
            throw new Error.FailedLogic(
                new LogicError.InvalidBlockRule(0, this.symbolTable.formatRule(convertedRule)));
          }
          TrustedOrigins ruleTrustedOrigins =
              TrustedOrigins.fromScopes(
                  convertedRule.scopes(), blockTrustedOrigins, i + 1, this.publicKeyToBlockId);
          world.addRule((long) i + 1, ruleTrustedOrigins, convertedRule);
        }
      }
    }
  }

  public Authorizer addToken(Biscuit token) throws Error.FailedLogic {
    if (this.token != null) {
      throw new Error.FailedLogic(new LogicError.AuthorizerNotEmpty());
    }

    this.token = token;
    updateOnToken();
    return this;
  }

  public Either<Map<Integer, List<Error>>, Authorizer> addDatalog(String s) {
    Either<Map<Integer, List<org.biscuitsec.biscuit.token.builder.parser.Error>>, Tuple4<List<org.biscuitsec.biscuit.token.builder.Fact>, List<org.biscuitsec.biscuit.token.builder.Rule>, List<org.biscuitsec.biscuit.token.builder.Check>, List<org.biscuitsec.biscuit.token.builder.Scope>>> result = Parser
        .datalogComponents(s);

    if (result.isLeft()) {
      Map<Integer, List<org.biscuitsec.biscuit.token.builder.parser.Error>> errors = result.getLeft();
      Map<Integer, List<Error>> errorMap = new HashMap<>();
      for (Map.Entry<Integer, List<org.biscuitsec.biscuit.token.builder.parser.Error>> entry : errors.entrySet()) {
        List<Error> errorsList = new ArrayList<>();
        for (org.biscuitsec.biscuit.token.builder.parser.Error error : entry.getValue()) {
          errorsList.add(new Error.Parser(error));
        }
        errorMap.put(entry.getKey(), errorsList);
      }
      return Either.left(errorMap);
    }

    Tuple4<List<org.biscuitsec.biscuit.token.builder.Fact>, List<org.biscuitsec.biscuit.token.builder.Rule>, List<org.biscuitsec.biscuit.token.builder.Check>, List<org.biscuitsec.biscuit.token.builder.Scope>> components = result
        .get();
    components._1.forEach(this::addFact);
    components._2.forEach(this::addRule);
    components._3.forEach(this::addCheck);

    return Either.right(this);
  }

  public Authorizer addFact(org.biscuitsec.biscuit.token.builder.Fact fact) {
    world.addFact(Origin.authorizer(), fact.convert(symbolTable));
    return this;
  }

  public Authorizer addFact(String s) throws Error.Parser {
    Either<
            org.biscuitsec.biscuit.token.builder.parser.Error,
            Tuple2<String, org.biscuitsec.biscuit.token.builder.Fact>>
        res = Parser.fact(s);

    if (res.isLeft()) {
      throw new Error.Parser(res.getLeft());
    }

    Tuple2<String, org.biscuitsec.biscuit.token.builder.Fact> t = res.get();

    return this.addFact(t._2);
  }

  public Authorizer addRule(org.biscuitsec.biscuit.token.builder.Rule rule) {
    org.biscuitsec.biscuit.datalog.Rule r = rule.convert(symbolTable);
    TrustedOrigins ruleTrustedOrigins =
        TrustedOrigins.fromScopes(
            r.scopes(), this.authorizerTrustedOrigins(), Long.MAX_VALUE, this.publicKeyToBlockId);
    world.addRule(Long.MAX_VALUE, ruleTrustedOrigins, r);
    return this;
  }

  public Authorizer addRule(String s) throws Error.Parser {
    Either<
            org.biscuitsec.biscuit.token.builder.parser.Error,
            Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule>>
        res = Parser.rule(s);

    if (res.isLeft()) {
      throw new Error.Parser(res.getLeft());
    }

    Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule> t = res.get();

    return addRule(t._2);
  }

  public TrustedOrigins authorizerTrustedOrigins() {
    return TrustedOrigins.fromScopes(
        this.scopes, TrustedOrigins.defaultOrigins(), Long.MAX_VALUE, this.publicKeyToBlockId);
  }

  public Authorizer addCheck(org.biscuitsec.biscuit.token.builder.Check check) {
    this.checks.add(check);
    return this;
  }

  public Authorizer addCheck(String s) throws Error.Parser {
    Either<
            org.biscuitsec.biscuit.token.builder.parser.Error,
            Tuple2<String, org.biscuitsec.biscuit.token.builder.Check>>
        res = Parser.check(s);

    if (res.isLeft()) {
      throw new Error.Parser(res.getLeft());
    }

    Tuple2<String, org.biscuitsec.biscuit.token.builder.Check> t = res.get();

    return addCheck(t._2);
  }

  public Authorizer setTime() throws Error.Language {
    world.addFact(
        Origin.authorizer(), Utils.fact("time", List.of(Utils.date(new Date()))).convert(symbolTable));
    return this;
  }

  public List<String> getRevocationIds() throws Error {
    ArrayList<String> ids = new ArrayList<>();

    final org.biscuitsec.biscuit.token.builder.Rule getRevocationIds =
        Utils.rule(
            "revocation_id",
            List.of(Utils.var("id")),
            List.of(Utils.pred("revocation_id", List.of(Utils.var("id")))));

    this.query(getRevocationIds).stream()
        .forEach(
            fact -> {
              fact.terms().stream()
                  .forEach(
                      id -> {
                        if (id instanceof Term.Str) {
                          ids.add(((Term.Str) id).getValue());
                        }
                      });
            });

    return ids;
  }

  public Authorizer allow() {
    ArrayList<org.biscuitsec.biscuit.token.builder.Rule> q = new ArrayList<>();

    q.add(
        Utils.constrainedRule(
            "allow",
            new ArrayList<>(),
            new ArrayList<>(),
            List.of(new Expression.Value(new Term.Bool(true)))));

    this.policies.add(new Policy(q, Policy.Kind.ALLOW));
    return this;
  }

  public Authorizer deny() {
    ArrayList<org.biscuitsec.biscuit.token.builder.Rule> q = new ArrayList<>();

    q.add(
        Utils.constrainedRule(
            "deny",
            new ArrayList<>(),
            new ArrayList<>(),
            List.of(new Expression.Value(new Term.Bool(true)))));

    this.policies.add(new Policy(q, Policy.Kind.DENY));
    return this;
  }

  public Authorizer addPolicy(String s) throws Error.Parser {
    Either<org.biscuitsec.biscuit.token.builder.parser.Error, Tuple2<String, Policy>> res =
        Parser.policy(s);

    if (res.isLeft()) {
      throw new Error.Parser(res.getLeft());
    }

    Tuple2<String, Policy> t = res.get();

    this.policies.add(t._2);
    return this;
  }

  public Authorizer addPolicy(Policy p) {
    this.policies.add(p);
    return this;
  }

  public Authorizer addScope(Scope s) {
    this.scopes.add(s);
    return this;
  }

  public Set<org.biscuitsec.biscuit.token.builder.Fact> query(
      org.biscuitsec.biscuit.token.builder.Rule query) throws Error {
    return this.query(query, new RunLimits());
  }

  public Set<org.biscuitsec.biscuit.token.builder.Fact> query(String s) throws Error {
    Either<
            org.biscuitsec.biscuit.token.builder.parser.Error,
            Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule>>
        res = Parser.rule(s);

    if (res.isLeft()) {
      throw new Error.Parser(res.getLeft());
    }

    Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule> t = res.get();

    return query(t._2);
  }

  public Set<org.biscuitsec.biscuit.token.builder.Fact> query(
      org.biscuitsec.biscuit.token.builder.Rule query, RunLimits limits) throws Error {
    world.run(limits, symbolTable);

    org.biscuitsec.biscuit.datalog.Rule rule = query.convert(symbolTable);
    TrustedOrigins ruleTrustedorigins =
        TrustedOrigins.fromScopes(
            rule.scopes(),
            TrustedOrigins.defaultOrigins(),
            Long.MAX_VALUE,
            this.publicKeyToBlockId);

    FactSet facts = world.queryRule(rule, Long.MAX_VALUE, ruleTrustedorigins, symbolTable);
    Set<org.biscuitsec.biscuit.token.builder.Fact> s = new HashSet<>();

    for (Iterator<org.biscuitsec.biscuit.datalog.Fact> it = facts.stream().iterator();
        it.hasNext(); ) {
      org.biscuitsec.biscuit.datalog.Fact f = it.next();
      s.add(org.biscuitsec.biscuit.token.builder.Fact.convertFrom(f, symbolTable));
    }

    return s;
  }

  public Set<org.biscuitsec.biscuit.token.builder.Fact> query(String s, RunLimits limits)
      throws Error {
    Either<
            org.biscuitsec.biscuit.token.builder.parser.Error,
            Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule>>
        res = Parser.rule(s);

    if (res.isLeft()) {
      throw new Error.Parser(res.getLeft());
    }

    Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule> t = res.get();

    return query(t._2, limits);
  }

  public Long authorize() throws Error {
    return this.authorize(new RunLimits());
  }

  public Long authorize(RunLimits limits) throws Error {
    Instant timeLimit = Instant.now().plus(limits.getMaxTime());
    List<FailedCheck> errors = new LinkedList<>();

    TrustedOrigins authorizerTrustedOrigins = this.authorizerTrustedOrigins();

    world.run(limits, symbolTable);

    for (int i = 0; i < this.checks.size(); i++) {
      org.biscuitsec.biscuit.datalog.Check c = this.checks.get(i).convert(symbolTable);
      boolean successful = false;

      for (int j = 0; j < c.queries().size(); j++) {
        boolean res = false;
        org.biscuitsec.biscuit.datalog.Rule query = c.queries().get(j);
        TrustedOrigins ruleTrustedOrigins =
            TrustedOrigins.fromScopes(
                query.scopes(), authorizerTrustedOrigins, Long.MAX_VALUE, this.publicKeyToBlockId);
        switch (c.kind()) {
          case ONE:
            res = world.queryMatch(query, Long.MAX_VALUE, ruleTrustedOrigins, symbolTable);
            break;
          case ALL:
            res = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable);
            break;
          default:
            throw new RuntimeException("unmapped kind");
        }

        if (Instant.now().compareTo(timeLimit) >= 0) {
          throw new Error.Timeout();
        }

        if (res) {
          successful = true;
          break;
        }
      }

      if (!successful) {
        errors.add(new FailedCheck.FailedAuthorizer(i, symbolTable.formatCheck(c)));
      }
    }

    if (token != null) {
      TrustedOrigins authorityTrustedOrigins =
          TrustedOrigins.fromScopes(
              token.authority.getScopes(),
              TrustedOrigins.defaultOrigins(),
              0,
              this.publicKeyToBlockId);

      for (int j = 0; j < token.authority.getChecks().size(); j++) {
        boolean successful = false;

        org.biscuitsec.biscuit.token.builder.Check c =
            org.biscuitsec.biscuit.token.builder.Check.convertFrom(
                token.authority.getChecks().get(j), token.symbolTable);
        org.biscuitsec.biscuit.datalog.Check check = c.convert(symbolTable);

        for (int k = 0; k < check.queries().size(); k++) {
          boolean res = false;
          org.biscuitsec.biscuit.datalog.Rule query = check.queries().get(k);
          TrustedOrigins ruleTrustedOrigins =
              TrustedOrigins.fromScopes(
                  query.scopes(), authorityTrustedOrigins, 0, this.publicKeyToBlockId);
          switch (check.kind()) {
            case ONE:
              res = world.queryMatch(query, (long) 0, ruleTrustedOrigins, symbolTable);
              break;
            case ALL:
              res = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable);
              break;
            default:
              throw new RuntimeException("unmapped kind");
          }

          if (Instant.now().compareTo(timeLimit) >= 0) {
            throw new Error.Timeout();
          }

          if (res) {
            successful = true;
            break;
          }
        }

        if (!successful) {
          errors.add(new FailedCheck.FailedBlock(0, j, symbolTable.formatCheck(check)));
        }
      }
    }

    Option<Either<Integer, Integer>> policyResult = Option.none();
    policies_test:
    for (int i = 0; i < this.policies.size(); i++) {
      Policy policy = this.policies.get(i);

      for (int j = 0; j < policy.queries().size(); j++) {
        org.biscuitsec.biscuit.datalog.Rule query = policy.queries().get(j).convert(symbolTable);
        TrustedOrigins policyTrustedOrigins =
            TrustedOrigins.fromScopes(
                query.scopes(), authorizerTrustedOrigins, Long.MAX_VALUE, this.publicKeyToBlockId);
        boolean res = world.queryMatch(query, Long.MAX_VALUE, policyTrustedOrigins, symbolTable);

        if (Instant.now().compareTo(timeLimit) >= 0) {
          throw new Error.Timeout();
        }

        if (res) {
          if (this.policies.get(i).kind() == Policy.Kind.ALLOW) {
            policyResult = Option.some(Right(i));
          } else {
            policyResult = Option.some(Left(i));
          }
          break policies_test;
        }
      }
    }

    if (token != null) {
      for (int i = 0; i < token.blocks.size(); i++) {
        org.biscuitsec.biscuit.token.Block b = token.blocks.get(i);
        TrustedOrigins blockTrustedOrigins =
            TrustedOrigins.fromScopes(
                b.getScopes(), TrustedOrigins.defaultOrigins(), i + 1, this.publicKeyToBlockId);
        SymbolTable blockSymbolTable = token.symbolTable;
        if (b.getExternalKey().isDefined()) {
          blockSymbolTable = new SymbolTable(b.getSymbolTable(), b.getPublicKeys());
        }

        for (int j = 0; j < b.getChecks().size(); j++) {
          boolean successful = false;

          org.biscuitsec.biscuit.token.builder.Check c =
              org.biscuitsec.biscuit.token.builder.Check.convertFrom(
                  b.getChecks().get(j), blockSymbolTable);
          org.biscuitsec.biscuit.datalog.Check check = c.convert(symbolTable);

          for (int k = 0; k < check.queries().size(); k++) {
            boolean res = false;
            org.biscuitsec.biscuit.datalog.Rule query = check.queries().get(k);
            TrustedOrigins ruleTrustedOrigins =
                TrustedOrigins.fromScopes(
                    query.scopes(), blockTrustedOrigins, i + 1, this.publicKeyToBlockId);
            switch (check.kind()) {
              case ONE:
                res = world.queryMatch(query, (long) i + 1, ruleTrustedOrigins, symbolTable);
                break;
              case ALL:
                res = world.queryMatchAll(query, ruleTrustedOrigins, symbolTable);
                break;
              default:
                throw new RuntimeException("unmapped kind");
            }

            if (Instant.now().compareTo(timeLimit) >= 0) {
              throw new Error.Timeout();
            }

            if (res) {
              successful = true;
              break;
            }
          }

          if (!successful) {
            errors.add(new FailedCheck.FailedBlock(i + 1, j, symbolTable.formatCheck(check)));
          }
        }
      }
    }

    if (policyResult.isDefined()) {
      Either<Integer, Integer> e = policyResult.get();
      if (e.isRight()) {
        if (errors.isEmpty()) {
          return e.get().longValue();
        } else {
          throw new Error.FailedLogic(
              new LogicError.Unauthorized(new LogicError.MatchedPolicy.Allow(e.get()), errors));
        }
      } else {
        throw new Error.FailedLogic(
            new LogicError.Unauthorized(new LogicError.MatchedPolicy.Deny(e.getLeft()), errors));
      }
    } else {
      throw new Error.FailedLogic(new LogicError.NoMatchingPolicy(errors));
    }
  }

  public String formatWorld() {
    StringBuilder facts = new StringBuilder();
    for (Map.Entry<Origin, HashSet<org.biscuitsec.biscuit.datalog.Fact>> entry :
        this.world.getFacts().facts().entrySet()) {
      facts.append("\n\t\t" + entry.getKey() + ":");
      for (org.biscuitsec.biscuit.datalog.Fact f : entry.getValue()) {
        facts.append("\n\t\t\t");
        facts.append(this.symbolTable.formatFact(f));
      }
    }
    final List<String> rules =
        this.world.getRules().stream()
            .map((r) -> this.symbolTable.formatRule(r))
            .collect(Collectors.toList());

    List<String> checks = new ArrayList<>();

    for (int j = 0; j < this.checks.size(); j++) {
      checks.add("Authorizer[" + j + "]: " + this.checks.get(j).toString());
    }

    if (this.token != null) {
      for (int j = 0; j < this.token.authority.getChecks().size(); j++) {
        checks.add(
            "Block[0]["
                + j
                + "]: "
                + token.symbolTable.formatCheck(this.token.authority.getChecks().get(j)));
      }

      for (int i = 0; i < this.token.blocks.size(); i++) {
        Block b = this.token.blocks.get(i);

        SymbolTable blockSymbolTable = token.symbolTable;
        if (b.getExternalKey().isDefined()) {
          blockSymbolTable = new SymbolTable(b.getSymbolTable(), b.getPublicKeys());
        }

        for (int j = 0; j < b.getChecks().size(); j++) {
          checks.add(
              "Block[" + (i + 1) + "][" + j + "]: " + blockSymbolTable.formatCheck(b.getChecks().get(j)));
        }
      }
    }

    return "World {\n\tfacts: ["
        + facts.toString()
        // String.join(",\n\t\t", facts) +
        + "\n\t],\n\trules: [\n\t\t"
        + String.join(",\n\t\t", rules)
        + "\n\t],\n\tchecks: [\n\t\t"
        + String.join(",\n\t\t", checks)
        + "\n\t]\n}";
  }

  public FactSet getFacts() {
    return this.world.getFacts();
  }

  public RuleSet getRules() {
    return this.world.getRules();
  }

  public List<Tuple2<Long, List<Check>>> getChecks() {
    List<Tuple2<Long, List<Check>>> allChecks = new ArrayList<>();
    if (!this.checks.isEmpty()) {
      allChecks.add(new Tuple2<>(Long.MAX_VALUE, this.checks));
    }

    List<Check> authorityChecks = new ArrayList<>();
    for (org.biscuitsec.biscuit.datalog.Check check : this.token.authority.getChecks()) {
      authorityChecks.add(Check.convertFrom(check, this.token.symbolTable));
    }
    if (!authorityChecks.isEmpty()) {
      allChecks.add(new Tuple2<>((long) 0, authorityChecks));
    }

    long count = 1;
    for (Block block : this.token.blocks) {
      List<Check> blockChecks = new ArrayList<>();

      if (block.getExternalKey().isDefined()) {
        SymbolTable blockSymbolTable = new SymbolTable(block.getSymbolTable(), block.getPublicKeys());
        for (org.biscuitsec.biscuit.datalog.Check check : block.getChecks()) {
          blockChecks.add(Check.convertFrom(check, blockSymbolTable));
        }
      } else {
        for (org.biscuitsec.biscuit.datalog.Check check : block.getChecks()) {
          blockChecks.add(Check.convertFrom(check, token.symbolTable));
        }
      }
      if (!blockChecks.isEmpty()) {
        allChecks.add(new Tuple2<>(count, blockChecks));
      }
      count += 1;
    }

    return allChecks;
  }

  public List<Policy> getPolicies() {
    return this.policies;
  }

  public SymbolTable getSymbolTable() {
    return symbolTable;
  }
}
