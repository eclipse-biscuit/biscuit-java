package org.biscuitsec.biscuit.builder;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.builder.Block;
import org.biscuitsec.biscuit.token.builder.Expression;
import org.biscuitsec.biscuit.token.builder.Term;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class BuilderTest {

    @Test
    public void testBuild() throws Error.Language, Error.SymbolTableOverlap, Error.FormatError {
        SecureRandom rng = new SecureRandom();
        KeyPair root = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, rng);
        SymbolTable symbols = Biscuit.defaultSymbolTable();

        Block authority_builder = new Block();
        authority_builder.addFact(Utils.fact("revocation_id", Arrays.asList(Utils.date(Date.from(Instant.now())))));
        authority_builder.addFact(Utils.fact("right", Arrays.asList(Utils.s("admin"))));
        authority_builder.addRule(Utils.constrainedRule("right",
                Arrays.asList(Utils.s("namespace"), Utils.var("tenant"), Utils.var("namespace"), Utils.var("operation")),
                Arrays.asList(Utils.pred("ns_operation", Arrays.asList(Utils.s("namespace"), Utils.var("tenant"), Utils.var("namespace"), Utils.var("operation")))),
                Arrays.asList(
                        new Expression.Binary(
                                Expression.Op.Contains,
                                new Expression.Value(Utils.var("operation")),
                                new Expression.Value(new Term.Set(new HashSet<>(Arrays.asList(
                                        Utils.s("create_topic"),
                                        Utils.s("get_topic"),
                                        Utils.s("get_topics")
                                )))))
                )
        ));
        authority_builder.addRule(Utils.constrainedRule("right",
                Arrays.asList(Utils.s("topic"), Utils.var("tenant"), Utils.var("namespace"), Utils.var("topic"), Utils.var("operation")),
                Arrays.asList(Utils.pred("topic_operation", Arrays.asList(Utils.s("topic"), Utils.var("tenant"), Utils.var("namespace"), Utils.var("topic"), Utils.var("operation")))),
                Arrays.asList(
                        new Expression.Binary(
                                Expression.Op.Contains,
                                new Expression.Value(Utils.var("operation")),
                                new Expression.Value(new Term.Set(new HashSet<>(Arrays.asList(
                                        Utils.s("lookup")
                                )))))
                )
        ));

        org.biscuitsec.biscuit.token.Block authority = authority_builder.build(symbols);
        Biscuit rootBiscuit = Biscuit.make(rng, root, authority);

        System.out.println(rootBiscuit.print());

        assertNotNull(rootBiscuit);
    }

    @Test
    public void testStringValueOfAStringTerm() {
        assertEquals( "\"hello\"", new Term.Str("hello").toString() );
    }

    @Test
    public void testStringValueOfAnIntegerTerm() {
        assertEquals( "123", new Term.Integer(123).toString() );
    }

    @Test
    public void testStringValueOfAVariableTerm() {
        assertEquals( "$hello", new Term.Variable("hello").toString() );
    }

    @Test
    public void testStringValueOfASetTerm() {
        String actual = new Term.Set(Set.of(new Term.Str("a"), new Term.Str("b"), new Term.Integer((3)))).toString();
        assertTrue(actual.startsWith("["), "starts with [");
        assertTrue(actual.endsWith("]"), "ends with ]");
        assertTrue(actual.contains("\"a\""), "contains a");
        assertTrue(actual.contains("\"b\""), "contains b");
        assertTrue(actual.contains("3"), "contains 3");
    }

    @Test
    public void testStringValueOfAByteArrayTermIsJustTheArrayReferenceNotTheContents() {
        String string = new Term.Bytes("Hello".getBytes(StandardCharsets.UTF_8)).toString();
        assertTrue(string.startsWith("hex:"), "starts with hex prefix");
    }

    @Test
    public void testArrayValueIsCopy() {
        byte[] someBytes = "Hello".getBytes(StandardCharsets.UTF_8);
        Term.Bytes term = new Term.Bytes(someBytes);
        assertTrue(Arrays.equals(someBytes, term.getValue()), "same content");
        assertNotEquals(System.identityHashCode(someBytes), System.identityHashCode(term.getValue()), "different objects");
    }
}
