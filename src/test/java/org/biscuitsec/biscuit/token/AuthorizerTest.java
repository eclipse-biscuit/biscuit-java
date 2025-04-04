package org.biscuitsec.biscuit.token;

import static org.biscuitsec.biscuit.token.builder.Utils.constrainedRule;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import biscuit.format.schema.Schema;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.error.Error.Parser;
import org.biscuitsec.biscuit.token.builder.Expression;
import org.biscuitsec.biscuit.token.builder.Term;
import org.junit.jupiter.api.Test;

public class AuthorizerTest {

  @Test
  public void testAuthorizerPolicy() throws Parser {
    Authorizer authorizer = new Authorizer();
    List<Policy> policies = authorizer.getPolicies();
    authorizer.deny();
    assertEquals(1, policies.size());

    authorizer.addPolicy(
        new Policy(
            Arrays.asList(
                constrainedRule(
                    "deny",
                    new ArrayList<>(),
                    new ArrayList<>(),
                    Arrays.asList(new Expression.Value(new Term.Bool(true))))),
            Policy.Kind.DENY));
    assertEquals(2, policies.size());

    authorizer.addPolicy("deny if true");
    assertEquals(3, policies.size());
  }

  @Test
  public void testPuttingSomeFactsInBiscuitAndGettingThemBackOutAgain() throws Exception {

    KeyPair keypair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, new SecureRandom());

    Biscuit token =
        Biscuit.builder(keypair)
            .addAuthorityFact("email(\"bob@example.com\")")
            .addAuthorityFact("id(123)")
            .addAuthorityFact("enabled(true)")
            .addAuthorityFact("perms([1,2,3])")
            .build();

    Authorizer authorizer =
        Biscuit.fromBase64Url(token.serializeBase64Url(), keypair.getPublicKey())
            .verify(keypair.getPublicKey())
            .authorizer();

    Term emailTerm = queryFirstResult(authorizer, "emailfact($name) <- email($name)");
    assertEquals("bob@example.com", ((Term.Str) emailTerm).getValue());

    Term idTerm = queryFirstResult(authorizer, "idfact($name) <- id($name)");
    assertEquals(123, ((Term.Integer) idTerm).getValue());

    Term enabledTerm = queryFirstResult(authorizer, "enabledfact($name) <- enabled($name)");
    assertEquals(true, ((Term.Bool) enabledTerm).getValue());

    Term permsTerm = queryFirstResult(authorizer, "permsfact($name) <- perms($name)");
    assertEquals(
        Set.of(new Term.Integer(1), new Term.Integer(2), new Term.Integer(3)),
        ((Term.Set) permsTerm).getValue());
  }

  @Test
  public void testDatalogAuthorizer() throws Exception {
    KeyPair keypair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, new SecureRandom());

    Biscuit token = Biscuit.builder(keypair)
        .addAuthorityFact("email(\"bob@example.com\")")
        .addAuthorityFact("id(123)")
        .addAuthorityFact("enabled(true)")
        .addAuthorityFact("perms([1,2,3])")
        .build();

    Authorizer authorizer = Biscuit.fromBase64Url(token.serializeBase64Url(), keypair.getPublicKey())
        .verify(keypair.getPublicKey())
        .authorizer();

    String l0 = "right($email) <- email($email)";
    String l1 = "check if right(\"bob@example.com\")";
    String datalog = String.join(";", Arrays.asList(l0, l1));
    authorizer.addDatalog(datalog);
    authorizer.addPolicy("allow if true");

    assertDoesNotThrow(() -> authorizer.authorize());

    Term emailTerm = queryFirstResult(authorizer, "right($address) <- email($address)");
    assertEquals("bob@example.com", ((Term.Str) emailTerm).getValue());
  }

  private static Term queryFirstResult(Authorizer authorizer, String query) throws Error {
    return authorizer.query(query).iterator().next().terms().get(0);
  }
}
