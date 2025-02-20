package org.biscuitsec.biscuit.token;

import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.FactSet;
import org.biscuitsec.biscuit.datalog.RuleSet;
import org.biscuitsec.biscuit.datalog.RunLimits;
import org.biscuitsec.biscuit.datalog.Origin;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.datalog.TrustedOrigins;
import org.biscuitsec.biscuit.datalog.World;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.error.FailedCheck;
import org.biscuitsec.biscuit.error.LogicError;
import org.biscuitsec.biscuit.token.builder.Expression;
import org.biscuitsec.biscuit.token.builder.Utils;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import io.vavr.control.Option;
import org.biscuitsec.biscuit.datalog.Scope;
import org.biscuitsec.biscuit.token.builder.Check;
import org.biscuitsec.biscuit.token.builder.Term;
import org.biscuitsec.biscuit.token.builder.parser.Parser;

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

import static io.vavr.API.Left;
import static io.vavr.API.Right;

/**
 * Token verification class
 */
public class Authorizer {
    Biscuit token;
    List<org.biscuitsec.biscuit.token.builder.Check> checks;
    List<Policy> policies;
    List<Scope> scopes;
    HashMap<Long, List<Long>> publicKeyToBlockId;
    World world;
    SymbolTable symbols;

    private Authorizer(Biscuit token, World w) throws Error.FailedLogic {
        this.token = token;
        this.world = w;
        this.symbols = new SymbolTable(this.token.symbols);
        this.checks = new ArrayList<>();
        this.policies = new ArrayList<>();
        this.scopes = new ArrayList<>();
        this.publicKeyToBlockId = new HashMap<>();
        updateOnToken();
    }

    /**
     * Creates an empty authorizer
     * <p>
     * used to apply policies when unauthenticated (no token)
     * and to preload an authorizer that is cloned for each new request
     */
    public Authorizer() {
        this.world = new World();
        this.symbols = Biscuit.defaultSymbolTable();
        this.checks = new ArrayList<>();
        this.policies = new ArrayList<>();
        this.scopes = new ArrayList<>();
        this.publicKeyToBlockId = new HashMap<>();
    }

    private Authorizer(Biscuit token, List<org.biscuitsec.biscuit.token.builder.Check> checks, List<Policy> policies,
                       World world, SymbolTable symbols) {
        this.token = token;
        this.checks = checks;
        this.policies = policies;
        this.world = world;
        this.symbols = symbols;
        this.scopes = new ArrayList<>();
        this.publicKeyToBlockId = new HashMap<>();
    }

    /**
     * Creates a authorizer for a token
     * <p>
     * also checks that the token is valid for this root public key
     *
     * @param token
     * @return Authorizer
     */
    static public Authorizer make(Biscuit token) throws Error.FailedLogic {
        return new Authorizer(token, new World());
    }

    public Authorizer clone() {
        return new Authorizer(this.token, new ArrayList<>(this.checks), new ArrayList<>(this.policies),
                new World(this.world), new SymbolTable(this.symbols));
    }

    public void updateOnToken() throws Error.FailedLogic {
        if (token != null) {
            for(long i =0; i < token.blocks.size(); i++) {
                Block block = token.blocks.get((int) i);

                if (block.externalKey.isDefined()) {
                    PublicKey pk = block.externalKey.get();
                    long newKeyId = this.symbols.insert(pk);
                    if (!this.publicKeyToBlockId.containsKey(newKeyId)) {
                        List<Long> l = new ArrayList<>();
                        l.add(i + 1);
                        this.publicKeyToBlockId.put(newKeyId, l);
                    } else {
                        this.publicKeyToBlockId.get(newKeyId).add(i + 1);
                    }
                }
            }

            TrustedOrigins authorityTrustedOrigins = TrustedOrigins.fromScopes(
                    token.authority.scopes,
                    TrustedOrigins.defaultOrigins(),
                    0,
                    this.publicKeyToBlockId
            );

            for (org.biscuitsec.biscuit.datalog.Fact fact : token.authority.facts) {
                org.biscuitsec.biscuit.datalog.Fact convertedFact = org.biscuitsec.biscuit.token.builder.Fact.convertFrom(fact, token.symbols).convert(this.symbols);
                world.addFact(new Origin(0), convertedFact);
            }
            for (org.biscuitsec.biscuit.datalog.Rule rule : token.authority.rules) {
                org.biscuitsec.biscuit.token.builder.Rule lRule = org.biscuitsec.biscuit.token.builder.Rule.convertFrom(rule, token.symbols);
                org.biscuitsec.biscuit.datalog.Rule convertedRule = lRule.convert(this.symbols);

                Either<String, org.biscuitsec.biscuit.token.builder.Rule> res = lRule.validateVariables();
                if(res.isLeft()){
                    throw new Error.FailedLogic(new LogicError.InvalidBlockRule(0, token.symbols.formatRule(convertedRule)));
                }
                TrustedOrigins ruleTrustedOrigins = TrustedOrigins.fromScopes(
                        convertedRule.scopes(),
                        authorityTrustedOrigins,
                        0,
                        this.publicKeyToBlockId
                );
                world.addRule((long) 0, ruleTrustedOrigins, convertedRule);
            }

            for(long i =0; i < token.blocks.size(); i++) {
                Block block = token.blocks.get((int)i);
                TrustedOrigins blockTrustedOrigins = TrustedOrigins.fromScopes(
                        block.scopes,
                        TrustedOrigins.defaultOrigins(),
                        i + 1,
                        this.publicKeyToBlockId
                );

                SymbolTable blockSymbols = token.symbols;

                if(block.externalKey.isDefined()) {
                    blockSymbols = new SymbolTable(block.symbols.symbols, block.publicKeys());
                }

                for (org.biscuitsec.biscuit.datalog.Fact fact : block.facts) {
                    org.biscuitsec.biscuit.datalog.Fact convertedFact = org.biscuitsec.biscuit.token.builder.Fact.convertFrom(fact, blockSymbols).convert(this.symbols);
                    world.addFact(new Origin(i + 1), convertedFact);
                }

                for (org.biscuitsec.biscuit.datalog.Rule rule : block.rules) {
                    org.biscuitsec.biscuit.token.builder.Rule sRule = org.biscuitsec.biscuit.token.builder.Rule.convertFrom(rule, blockSymbols);
                    org.biscuitsec.biscuit.datalog.Rule convertedRule = sRule.convert(this.symbols);

                    Either<String, org.biscuitsec.biscuit.token.builder.Rule> res = sRule.validateVariables();
                    if (res.isLeft()) {
                        throw new Error.FailedLogic(new LogicError.InvalidBlockRule(0, this.symbols.formatRule(convertedRule)));
                    }
                    TrustedOrigins ruleTrustedOrigins = TrustedOrigins.fromScopes(
                            convertedRule.scopes(),
                            blockTrustedOrigins,
                            i + 1,
                            this.publicKeyToBlockId
                    );
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

    public Authorizer addFact(org.biscuitsec.biscuit.token.builder.Fact fact) {
        world.addFact(Origin.authorizer(), fact.convert(symbols));
        return this;
    }

    public Authorizer addFact(String s) throws Error.Parser {
        Either<org.biscuitsec.biscuit.token.builder.parser.Error, Tuple2<String, org.biscuitsec.biscuit.token.builder.Fact>> res =
                Parser.fact(s);

        if (res.isLeft()) {
            throw new Error.Parser(res.getLeft());
        }

        Tuple2<String, org.biscuitsec.biscuit.token.builder.Fact> t = res.get();

        return this.addFact(t._2);
    }

    public Authorizer addRule(org.biscuitsec.biscuit.token.builder.Rule rule) {
       org.biscuitsec.biscuit.datalog.Rule r = rule.convert(symbols);
        TrustedOrigins ruleTrustedOrigins = TrustedOrigins.fromScopes(
                r.scopes(),
                this.authorizerTrustedOrigins(),
                Long.MAX_VALUE,
                this.publicKeyToBlockId
            );
        world.addRule(Long.MAX_VALUE, ruleTrustedOrigins, r);
        return this;
    }

    public TrustedOrigins authorizerTrustedOrigins() {
        return TrustedOrigins.fromScopes(
                this.scopes,
                TrustedOrigins.defaultOrigins(),
                Long.MAX_VALUE,
                this.publicKeyToBlockId
        );
    }

    public Authorizer addRule(String s) throws Error.Parser {
        Either<org.biscuitsec.biscuit.token.builder.parser.Error, Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule>> res =
                Parser.rule(s);

        if (res.isLeft()) {
            throw new Error.Parser(res.getLeft());
        }

        Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule> t = res.get();

        return addRule(t._2);
    }

    public Authorizer addCheck(org.biscuitsec.biscuit.token.builder.Check check) {
        this.checks.add(check);
        return this;
    }

    public Authorizer addCheck(String s) throws Error.Parser {
        Either<org.biscuitsec.biscuit.token.builder.parser.Error, Tuple2<String, org.biscuitsec.biscuit.token.builder.Check>> res =
                Parser.check(s);

        if (res.isLeft()) {
            throw new Error.Parser(res.getLeft());
        }

        Tuple2<String, org.biscuitsec.biscuit.token.builder.Check> t = res.get();

        return addCheck(t._2);
    }

    public Authorizer setTime() throws Error.Language {
        world.addFact(Origin.authorizer(), Utils.fact("time", List.of(Utils.date(new Date()))).convert(symbols));
        return this;
    }

    public List<String> getRevocationIds() throws Error {
        ArrayList<String> ids = new ArrayList<>();

        final org.biscuitsec.biscuit.token.builder.Rule getRevocationIds = Utils.rule(
                "revocation_id",
                List.of(Utils.var("id")),
                List.of(Utils.pred("revocation_id", List.of(Utils.var("id"))))
        );

        this.query(getRevocationIds).stream().forEach(fact -> {
            fact.terms().stream().forEach(id -> {
                if (id instanceof Term.Str) {
                    ids.add(((Term.Str) id).getValue());
                }
            });
        });

        return ids;
    }

    public Authorizer allow() {
        ArrayList<org.biscuitsec.biscuit.token.builder.Rule> q = new ArrayList<>();

        q.add(Utils.constrainedRule(
                "allow",
                new ArrayList<>(),
                new ArrayList<>(),
                List.of(new Expression.Value(new Term.Bool(true)))
        ));

        this.policies.add(new Policy(q, Policy.Kind.Allow));
        return this;
    }

    public Authorizer deny() {
        ArrayList<org.biscuitsec.biscuit.token.builder.Rule> q = new ArrayList<>();

        q.add(Utils.constrainedRule(
                "deny",
                new ArrayList<>(),
                new ArrayList<>(),
                List.of(new Expression.Value(new Term.Bool(true)))
        ));

        this.policies.add(new Policy(q, Policy.Kind.Deny));
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

    public Set<org.biscuitsec.biscuit.token.builder.Fact> query(org.biscuitsec.biscuit.token.builder.Rule query) throws Error {
        return this.query(query, new RunLimits());
    }

    public Set<org.biscuitsec.biscuit.token.builder.Fact> query(String s) throws Error {
        Either<org.biscuitsec.biscuit.token.builder.parser.Error, Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule>> res =
                Parser.rule(s);

        if (res.isLeft()) {
            throw new Error.Parser(res.getLeft());
        }

        Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule> t = res.get();

        return query(t._2);
    }

    public Set<org.biscuitsec.biscuit.token.builder.Fact> query(org.biscuitsec.biscuit.token.builder.Rule query, RunLimits limits) throws Error {
        world.run(limits, symbols);

        org.biscuitsec.biscuit.datalog.Rule rule = query.convert(symbols);
        TrustedOrigins ruleTrustedorigins = TrustedOrigins.fromScopes(
                rule.scopes(),
                TrustedOrigins.defaultOrigins(),
                Long.MAX_VALUE,
                this.publicKeyToBlockId
        );

        FactSet facts = world.queryRule(rule, Long.MAX_VALUE,
                ruleTrustedorigins, symbols);
        Set<org.biscuitsec.biscuit.token.builder.Fact> s = new HashSet<>();

        for (Iterator<org.biscuitsec.biscuit.datalog.Fact> it = facts.stream().iterator(); it.hasNext(); ) {
            org.biscuitsec.biscuit.datalog.Fact f = it.next();
            s.add(org.biscuitsec.biscuit.token.builder.Fact.convertFrom(f, symbols));
        }

        return s;
    }

    public Set<org.biscuitsec.biscuit.token.builder.Fact> query(String s, RunLimits limits) throws Error {
        Either<org.biscuitsec.biscuit.token.builder.parser.Error, Tuple2<String, org.biscuitsec.biscuit.token.builder.Rule>> res =
                Parser.rule(s);

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
        Instant timeLimit = Instant.now().plus(limits.maxTime);
        List<FailedCheck> errors = new LinkedList<>();
        Option<Either<Integer, Integer>> policyResult = Option.none();

        TrustedOrigins authorizerTrustedOrigins = this.authorizerTrustedOrigins();

        world.run(limits, symbols);

        for (int i = 0; i < this.checks.size(); i++) {
            org.biscuitsec.biscuit.datalog.Check c = this.checks.get(i).convert(symbols);
            boolean successful = false;

            for (int j = 0; j < c.queries().size(); j++) {
                boolean res = false;
                org.biscuitsec.biscuit.datalog.Rule query = c.queries().get(j);
                TrustedOrigins ruleTrustedOrigins = TrustedOrigins.fromScopes(
                        query.scopes(),
                        authorizerTrustedOrigins,
                        Long.MAX_VALUE,
                        this.publicKeyToBlockId
                );
                switch (c.kind()) {
                    case One:
                        res = world.queryMatch(query, Long.MAX_VALUE, ruleTrustedOrigins, symbols);
                        break;
                    case All:
                        res = world.queryMatchAll(query, ruleTrustedOrigins, symbols);
                        break;
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
                errors.add(new FailedCheck.FailedAuthorizer(i, symbols.formatCheck(c)));
            }
        }

        if (token != null) {
            TrustedOrigins authorityTrustedOrigins = TrustedOrigins.fromScopes(
                    token.authority.scopes,
                    TrustedOrigins.defaultOrigins(),
                    0,
                    this.publicKeyToBlockId
                );

            for (int j = 0; j < token.authority.checks.size(); j++) {
                boolean successful = false;

                org.biscuitsec.biscuit.token.builder.Check c = org.biscuitsec.biscuit.token.builder.Check.convertFrom(token.authority.checks.get(j), token.symbols);
                org.biscuitsec.biscuit.datalog.Check check = c.convert(symbols);

                for (int k = 0; k < check.queries().size(); k++) {
                    boolean res = false;
                    org.biscuitsec.biscuit.datalog.Rule query = check.queries().get(k);
                    TrustedOrigins ruleTrustedOrigins = TrustedOrigins.fromScopes(
                            query.scopes(),
                            authorityTrustedOrigins,
                            0,
                            this.publicKeyToBlockId
                    );
                    switch (check.kind()) {
                        case One:
                            res = world.queryMatch(query, (long)0, ruleTrustedOrigins, symbols);
                            break;
                        case All:
                            res = world.queryMatchAll(query, ruleTrustedOrigins, symbols);
                            break;
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
                    errors.add(new FailedCheck.FailedBlock(0, j, symbols.formatCheck(check)));
                }
            }
        }

        policies_test:
        for (int i = 0; i < this.policies.size(); i++) {
            Policy policy = this.policies.get(i);

            for (int j = 0; j < policy.queries.size(); j++) {
                org.biscuitsec.biscuit.datalog.Rule query = policy.queries.get(j).convert(symbols);
                TrustedOrigins policyTrustedOrigins = TrustedOrigins.fromScopes(
                        query.scopes(),
                        authorizerTrustedOrigins,
                        Long.MAX_VALUE,
                        this.publicKeyToBlockId
                );
                boolean res = world.queryMatch(query, Long.MAX_VALUE, policyTrustedOrigins, symbols);

                if (Instant.now().compareTo(timeLimit) >= 0) {
                    throw new Error.Timeout();
                }

                if (res) {
                    if (this.policies.get(i).kind == Policy.Kind.Allow) {
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
                TrustedOrigins blockTrustedOrigins = TrustedOrigins.fromScopes(
                        b.scopes,
                        TrustedOrigins.defaultOrigins(),
                        i+1,
                        this.publicKeyToBlockId
                );
                SymbolTable blockSymbols = token.symbols;
                if(b.externalKey.isDefined()) {
                    blockSymbols = new SymbolTable(b.symbols.symbols, b.publicKeys());
                }

                for (int j = 0; j < b.checks.size(); j++) {
                    boolean successful = false;

                    org.biscuitsec.biscuit.token.builder.Check c = org.biscuitsec.biscuit.token.builder.Check.convertFrom(b.checks.get(j), blockSymbols);
                    org.biscuitsec.biscuit.datalog.Check check = c.convert(symbols);

                    for (int k = 0; k < check.queries().size(); k++) {
                        boolean res = false;
                        org.biscuitsec.biscuit.datalog.Rule query = check.queries().get(k);
                        TrustedOrigins ruleTrustedOrigins = TrustedOrigins.fromScopes(
                                query.scopes(),
                                blockTrustedOrigins,
                                i+1,
                                this.publicKeyToBlockId
                        );
                        switch (check.kind()) {
                            case One:
                                res = world.queryMatch(query, (long)i+1, ruleTrustedOrigins, symbols);
                                break;
                            case All:
                                res = world.queryMatchAll(query, ruleTrustedOrigins, symbols);
                                break;
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
                        errors.add(new FailedCheck.FailedBlock(i + 1, j, symbols.formatCheck(check)));
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
                    throw new Error.FailedLogic(new LogicError.Unauthorized(new LogicError.MatchedPolicy.Allow(e.get()), errors));
                }
            } else {
                throw new Error.FailedLogic(new LogicError.Unauthorized(new LogicError.MatchedPolicy.Deny(e.getLeft()), errors));
            }
        } else {
            throw new Error.FailedLogic(new LogicError.NoMatchingPolicy(errors));
        }
    }

    public String formatWorld() {
        StringBuilder facts = new StringBuilder();
        for(Map.Entry<Origin, HashSet<org.biscuitsec.biscuit.datalog.Fact>> entry: this.world.facts().facts().entrySet()) {
            facts.append("\n\t\t"+entry.getKey()+":");
            for(org.biscuitsec.biscuit.datalog.Fact f: entry.getValue()) {
                facts.append("\n\t\t\t");
                facts.append(this.symbols.formatFact(f));
            }
        }
        final List<String> rules = this.world.rules().stream().map((r) -> this.symbols.formatRule(r)).collect(Collectors.toList());

        List<String> checks = new ArrayList<>();

        for (int j = 0; j < this.checks.size(); j++) {
            checks.add("Authorizer[" + j + "]: " + this.checks.get(j).toString());
        }

        if (this.token != null) {
            for (int j = 0; j < this.token.authority.checks.size(); j++) {
                checks.add("Block[0][" + j + "]: " + token.symbols.formatCheck(this.token.authority.checks.get(j)));
            }

            for (int i = 0; i < this.token.blocks.size(); i++) {
                Block b = this.token.blocks.get(i);

                SymbolTable blockSymbols = token.symbols;
                if(b.externalKey.isDefined()) {
                    blockSymbols = new SymbolTable(b.symbols.symbols, b.publicKeys());
                }

                for (int j = 0; j < b.checks.size(); j++) {
                    checks.add("Block[" + (i+1) + "][" + j + "]: " + blockSymbols.formatCheck(b.checks.get(j)));
                }
            }
        }

        return "World {\n\tfacts: [" +
                facts.toString() +
                //String.join(",\n\t\t", facts) +
                "\n\t],\n\trules: [\n\t\t" +
                String.join(",\n\t\t", rules) +
                "\n\t],\n\tchecks: [\n\t\t" +
                String.join(",\n\t\t", checks) +
                "\n\t]\n}";
    }

    public FactSet facts() {
        return this.world.facts();
    }

    public RuleSet rules() {
        return this.world.rules();
    }

    public List<Tuple2<Long, List<Check>>> checks() {
        List<Tuple2<Long, List<Check>>> allChecks = new ArrayList<>();
        if(!this.checks.isEmpty()) {
            allChecks.add(new Tuple2<>(Long.MAX_VALUE, this.checks));
        }

        List<Check> authorityChecks = new ArrayList<>();
        for(org.biscuitsec.biscuit.datalog.Check check: this.token.authority.checks) {
            authorityChecks.add(Check.convertFrom(check, this.token.symbols));
        }
        if(!authorityChecks.isEmpty()) {
            allChecks.add(new Tuple2<>((long) 0, authorityChecks));
        }

        long count = 1;
        for(Block block: this.token.blocks) {
            List<Check> blockChecks = new ArrayList<>();

            if(block.externalKey.isDefined()) {
                SymbolTable blockSymbols = new SymbolTable(block.symbols.symbols, block.publicKeys());
                for(org.biscuitsec.biscuit.datalog.Check check: block.checks) {
                    blockChecks.add(Check.convertFrom(check, blockSymbols));
                }
            } else {
                for(org.biscuitsec.biscuit.datalog.Check check: block.checks) {
                    blockChecks.add(Check.convertFrom(check, token.symbols));
                }
            }
            if(!blockChecks.isEmpty()) {
                allChecks.add(new Tuple2<>(count, blockChecks));
            }
            count += 1;
        }

        return allChecks;
    }

    public List<Policy> policies() {
        return this.policies;
    }
}
