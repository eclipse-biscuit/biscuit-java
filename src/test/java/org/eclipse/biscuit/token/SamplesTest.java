/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.eclipse.biscuit.token.Block.fromBytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import biscuit.format.schema.Schema;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import io.vavr.control.Option;
import io.vavr.control.Try;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.Rule;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.token.builder.Check;
import org.eclipse.biscuit.token.builder.parser.Parser;
import org.eclipse.biscuit.token.format.SignedBlock;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

class SamplesTest {
  final RunLimits runLimits = new RunLimits(500, 100, Duration.ofMillis(500));

  @TestFactory
  Stream<DynamicTest> jsonTest() {
    InputStream inputStream =
        Thread.currentThread().getContextClassLoader().getResourceAsStream("samples/samples.json");
    Gson gson = new Gson();
    Sample sample =
        gson.fromJson(new InputStreamReader(new BufferedInputStream(inputStream)), Sample.class);
    PublicKey publicKey =
        PublicKey.load(Schema.PublicKey.Algorithm.Ed25519, sample.root_public_key);
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, sample.root_private_key);
    return sample.testcases.stream().map(t -> processTestcase(t, publicKey, keyPair));
  }

  void compareBlocks(KeyPair root, List<Block> sampleBlocks, Biscuit token) throws Error {
    assertEquals(sampleBlocks.size(), 1 + token.blocks.size());
    Option<Biscuit> sampleToken = Option.none();
    Biscuit b =
        compareBlock(root, sampleToken, 0, sampleBlocks.get(0), token.authority, token.symbolTable);
    sampleToken = Option.some(b);

    for (int i = 0; i < token.blocks.size(); i++) {
      b =
          compareBlock(
              root,
              sampleToken,
              i + 1,
              sampleBlocks.get(i + 1),
              token.blocks.get(i),
              token.symbolTable);
      sampleToken = Option.some(b);
    }
  }

  Biscuit compareBlock(
      KeyPair root,
      Option<Biscuit> sampleToken,
      long sampleBlockIndex,
      Block sampleBlock,
      org.eclipse.biscuit.token.Block tokenBlock,
      SymbolTable tokenSymbols)
      throws Error {
    Option<PublicKey> sampleExternalKey = sampleBlock.getExternalKey();
    List<PublicKey> samplePublicKeys = sampleBlock.getPublicKeys();
    String sampleDatalog = sampleBlock.getCode().replace("\"", "\\\"");

    Either<
            Map<Integer, List<org.eclipse.biscuit.token.builder.parser.Error>>,
            org.eclipse.biscuit.token.builder.Block>
        outputSample = Parser.datalog(sampleBlockIndex, sampleDatalog);

    // the invalid block rule with unbound variable cannot be parsed
    if (outputSample.isLeft()) {
      return sampleToken.get();
    }

    Biscuit newSampleToken;
    if (!sampleToken.isDefined()) {
      org.eclipse.biscuit.token.builder.Biscuit builder =
          new org.eclipse.biscuit.token.builder.Biscuit(
              new SecureRandom(), root, Option.none(), outputSample.get());
      newSampleToken = builder.build();
    } else {
      Biscuit s = sampleToken.get();
      newSampleToken = s.attenuate(outputSample.get(), Schema.PublicKey.Algorithm.Ed25519);
    }

    org.eclipse.biscuit.token.Block generatedSampleBlock;
    if (!sampleToken.isDefined()) {
      generatedSampleBlock = newSampleToken.authority;
    } else {
      generatedSampleBlock = newSampleToken.blocks.get((int) sampleBlockIndex - 1);
    }

    System.out.println("generated block: ");
    System.out.println(generatedSampleBlock.print(newSampleToken.symbolTable));
    System.out.println("deserialized block: ");
    System.out.println(tokenBlock.print(newSampleToken.symbolTable));

    SymbolTable tokenBlockSymbols = tokenSymbols;
    SymbolTable generatedBlockSymbols = newSampleToken.symbolTable;
    assertEquals(
        generatedSampleBlock.printCode(generatedBlockSymbols),
        tokenBlock.printCode(tokenBlockSymbols));

    /* FIXME: to generate the same sample block,
        we need the samples to provide the external private key
    assertEquals(generatedSampleBlock, tokenBlock);
    assertArrayEquals(generatedSampleBlock.to_bytes().get(), tokenBlock.to_bytes().get());
    */

    return newSampleToken;
  }

  DynamicTest processTestcase(
      final TestCase testCase, final PublicKey publicKey, final KeyPair privateKey) {
    return DynamicTest.dynamicTest(
        testCase.title + ": " + testCase.filename,
        () -> {
          System.out.println("Testcase name: \"" + testCase.title + "\"");
          System.out.println("filename: \"" + testCase.filename + "\"");
          InputStream inputStream =
              Thread.currentThread()
                  .getContextClassLoader()
                  .getResourceAsStream("samples/" + testCase.filename);
          byte[] data = new byte[inputStream.available()];

          for (Map.Entry<String, JsonElement> validationEntry :
              testCase.validations.getAsJsonObject().entrySet()) {
            String validationName = validationEntry.getKey();
            JsonObject validation = validationEntry.getValue().getAsJsonObject();

            JsonObject expectedResult = validation.getAsJsonObject("result");
            String[] authorizerFacts =
                validation.getAsJsonPrimitive("authorizer_code").getAsString().split(";");
            Either<Throwable, Long> res =
                Try.of(
                        () -> {
                          inputStream.read(data);
                          Biscuit token = Biscuit.fromBytes(data, publicKey);
                          assertArrayEquals(token.serialize(), data);

                          List<org.eclipse.biscuit.token.Block> allBlocks = new ArrayList<>();
                          allBlocks.add(token.authority);
                          allBlocks.addAll(token.blocks);

                          compareBlocks(privateKey, testCase.token, token);

                          byte[] serBlockAuthority = token.authority.toBytes().get();
                          System.out.println(Arrays.toString(serBlockAuthority));
                          System.out.println(
                              Arrays.toString(token.serializedBiscuit.getAuthority().getBlock()));
                          org.eclipse.biscuit.token.Block deserBlockAuthority =
                              fromBytes(serBlockAuthority, token.authority.getExternalKey()).get();
                          assertEquals(
                              token.authority.print(token.symbolTable),
                              deserBlockAuthority.print(token.symbolTable));
                          assert (Arrays.equals(
                              serBlockAuthority,
                              token.serializedBiscuit.getAuthority().getBlock()));

                          for (int i = 0; i < token.blocks.size() - 1; i++) {
                            org.eclipse.biscuit.token.Block block = token.blocks.get(i);
                            SignedBlock signedBlock = token.serializedBiscuit.getBlocks().get(i);
                            byte[] serBlock = block.toBytes().get();
                            org.eclipse.biscuit.token.Block deserBlock =
                                fromBytes(serBlock, block.getExternalKey()).get();
                            assertEquals(
                                block.print(token.symbolTable),
                                deserBlock.print(token.symbolTable));
                            assert (Arrays.equals(serBlock, signedBlock.getBlock()));
                          }

                          List<RevocationIdentifier> revocationIds = token.revocationIdentifiers();
                          JsonArray validationRevocationIds =
                              validation.getAsJsonArray("revocation_ids");
                          assertEquals(revocationIds.size(), validationRevocationIds.size());
                          for (int i = 0; i < revocationIds.size(); i++) {
                            assertEquals(
                                validationRevocationIds.get(i).getAsString(),
                                revocationIds.get(i).toHex());
                          }

                          // TODO Add check of the token

                          Authorizer authorizer = token.authorizer();
                          System.out.println(token.print());
                          for (String f : authorizerFacts) {
                            f = f.trim();
                            if (!f.isEmpty()) {
                              if (f.startsWith("check if") || f.startsWith("check all")) {
                                authorizer.addCheck(f);
                              } else if (f.startsWith("allow if") || f.startsWith("deny if")) {
                                authorizer.addPolicy(f);
                              } else if (f.startsWith("revocation_id")) {
                                // do nothing
                              } else {
                                authorizer.addFact(f);
                              }
                            }
                          }
                          System.out.println(authorizer.formatWorld());
                          try {
                            Long authorizeResult = authorizer.authorize(runLimits);

                            if (validation.has("world") && !validation.get("world").isJsonNull()) {
                              World world =
                                  new Gson()
                                      .fromJson(
                                          validation.get("world").getAsJsonObject(), World.class);
                              world.fixOrigin();

                              World authorizerWorld = new World(authorizer);
                              assertEquals(world.factMap(), authorizerWorld.factMap());
                              assertEquals(world.rules, authorizerWorld.rules);
                              assertEquals(world.checks, authorizerWorld.checks);
                              assertEquals(world.policies, authorizerWorld.policies);
                            }

                            return authorizeResult;
                          } catch (Exception e) {

                            if (validation.has("world") && !validation.get("world").isJsonNull()) {
                              World world =
                                  new Gson()
                                      .fromJson(
                                          validation.get("world").getAsJsonObject(), World.class);
                              world.fixOrigin();

                              World authorizerWorld = new World(authorizer);
                              assertEquals(world.factMap(), authorizerWorld.factMap());
                              assertEquals(world.rules, authorizerWorld.rules);
                              assertEquals(world.checks, authorizerWorld.checks);
                              assertEquals(world.policies, authorizerWorld.policies);
                            }

                            throw e;
                          }
                        })
                    .toEither();

            if (expectedResult.has("Ok")) {
              if (res.isLeft()) {
                System.out.println(
                    "validation '"
                        + validationName
                        + "' expected result Ok("
                        + expectedResult.getAsJsonPrimitive("Ok").getAsLong()
                        + "), got error");
                throw res.getLeft();
              } else {
                assertEquals(expectedResult.getAsJsonPrimitive("Ok").getAsLong(), res.get());
              }
            } else {
              if (res.isLeft()) {
                if (res.getLeft() instanceof Error) {
                  Error e = (Error) res.getLeft();
                  System.out.println("validation '" + validationName + "' got error: " + e);
                  JsonElement errJson = e.toJson();
                  assertEquals(expectedResult.get("Err"), errJson);
                } else {
                  throw res.getLeft();
                }
              } else {
                throw new Exception(
                    "validation '"
                        + validationName
                        + "' expected result error("
                        + expectedResult.get("Err")
                        + "), got success: "
                        + res.get());
              }
            }
          }
        });
  }

  class Block {
    List<String> symbols;
    String code;

    @SuppressWarnings("checkstyle:MemberName")
    List<String> public_keys;

    @SuppressWarnings("checkstyle:MemberName")
    String external_key;

    int version;

    public List<String> getSymbols() {
      return symbols;
    }

    public void setSymbols(List<String> symbols) {
      this.symbols = symbols;
    }

    public String getCode() {
      return code;
    }

    public void setCode(String code) {
      this.code = code;
    }

    public List<PublicKey> getPublicKeys() {
      return this.public_keys.stream()
          .map(
              pk ->
                  Parser.publicKey(pk)
                      .fold(
                          e -> {
                            throw new IllegalArgumentException(e.toString());
                          },
                          r -> r._2))
          .collect(Collectors.toList());
    }

    public void setPublicKeys(List<PublicKey> publicKeys) {
      this.public_keys = publicKeys.stream().map(PublicKey::toString).collect(Collectors.toList());
    }

    public Option<PublicKey> getExternalKey() {
      if (this.external_key != null) {
        PublicKey externalKey =
            Parser.publicKey(this.external_key)
                .fold(
                    e -> {
                      throw new IllegalArgumentException(e.toString());
                    },
                    r -> r._2);
        return Option.of(externalKey);
      } else {
        return Option.none();
      }
    }

    public void setExternalKey(Option<PublicKey> externalKey) {
      this.external_key = externalKey.map(PublicKey::toString).getOrElse((String) null);
    }
  }

  class TestCase {
    String title;

    public String getTitle() {
      return title;
    }

    public void setTitle(String title) {
      this.title = title;
    }

    String filename;
    List<Block> token;
    JsonElement validations;

    public String getFilename() {
      return filename;
    }

    public void setFilename(String filename) {
      this.filename = filename;
    }

    public List<Block> getToken() {
      return token;
    }

    public void setTokens(List<Block> token) {
      this.token = token;
    }

    public JsonElement getValidations() {
      return validations;
    }

    public void setValidations(JsonElement validations) {
      this.validations = validations;
    }
  }

  class Sample {
    @SuppressWarnings("checkstyle:MemberName")
    String root_private_key;

    @SuppressWarnings("checkstyle:MethodName")
    public String getRoot_public_key() {
      return root_public_key;
    }

    @SuppressWarnings({"checkstyle:MethodName", "checkstyle:ParameterName"})
    public void setRoot_public_key(String root_public_key) {
      this.root_public_key = root_public_key;
    }

    @SuppressWarnings("checkstyle:MemberName")
    String root_public_key;

    List<TestCase> testcases;

    @SuppressWarnings("checkstyle:MethodName")
    public String getRoot_private_key() {
      return root_private_key;
    }

    @SuppressWarnings({"checkstyle:MethodName", "checkstyle:ParameterName"})
    public void setRoot_private_key(String root_private_key) {
      this.root_private_key = root_private_key;
    }

    public List<TestCase> getTestcases() {
      return testcases;
    }

    public void setTestcases(List<TestCase> testcases) {
      this.testcases = testcases;
    }
  }

  class World {
    List<FactSet> facts;
    List<RuleSet> rules;
    List<CheckSet> checks;
    List<String> policies;

    public World(
        List<FactSet> facts, List<RuleSet> rules, List<CheckSet> checks, List<String> policies) {
      this.facts = facts;
      this.rules = rules;
      this.checks = checks;
      this.policies = policies;
    }

    public World(Authorizer authorizer) {
      this.facts =
          authorizer.getFacts().facts().entrySet().stream()
              .map(
                  entry -> {
                    ArrayList<Long> origin = new ArrayList<>(entry.getKey().blockIds());
                    Collections.sort(origin);
                    ArrayList<String> facts =
                        new ArrayList<>(
                            entry.getValue().stream()
                                .map(f -> authorizer.getSymbolTable().formatFact(f))
                                .collect(Collectors.toList()));
                    Collections.sort(facts);

                    return new FactSet(origin, facts);
                  })
              .collect(Collectors.toList());

      HashMap<Long, List<String>> rules = new HashMap<>();
      for (List<Tuple2<Long, Rule>> l : authorizer.getRules().getRules().values()) {
        for (Tuple2<Long, Rule> t : l) {
          if (!rules.containsKey(t._1)) {
            rules.put(t._1, new ArrayList<>());
          }
          rules.get(t._1).add(authorizer.getSymbolTable().formatRule(t._2));
        }
      }
      for (Map.Entry<Long, List<String>> entry : rules.entrySet()) {
        Collections.sort(entry.getValue());
      }
      List<RuleSet> rulesets =
          rules.entrySet().stream()
              .map(entry -> new RuleSet(entry.getKey(), entry.getValue()))
              .collect(Collectors.toList());
      Collections.sort(rulesets);

      this.rules = rulesets;

      this.checks =
          authorizer.getChecks().stream()
              .map(
                  (Tuple2<Long, List<Check>> t) -> {
                    List<String> checks1 =
                        t._2.stream().map(c -> c.toString()).collect(Collectors.toList());
                    Collections.sort(checks1);
                    if (t._1 == null) {
                      return new CheckSet(checks1);
                    } else {
                      return new CheckSet(t._1, checks1);
                    }
                  })
              .collect(Collectors.toList());
      this.policies =
          authorizer.getPolicies().stream().map(p -> p.toString()).collect(Collectors.toList());
      Collections.sort(this.rules);
      Collections.sort(this.checks);
    }

    public void fixOrigin() {
      for (FactSet f : this.facts) {
        f.fixOrigin();
      }
      for (RuleSet r : this.rules) {
        r.fixOrigin();
      }
      Collections.sort(this.rules);
      for (CheckSet c : this.checks) {
        c.fixOrigin();
      }
      Collections.sort(this.checks);
    }

    public HashMap<List<Long>, List<String>> factMap() {
      HashMap<List<Long>, List<String>> worldFacts = new HashMap<>();
      for (FactSet f : this.facts) {
        worldFacts.put(f.origin, f.facts);
      }

      return worldFacts;
    }

    @Override
    public String toString() {
      return "World{\n"
          + "facts="
          + facts
          + ",\nrules="
          + rules
          + ",\nchecks="
          + checks
          + ",\npolicies="
          + policies
          + '}';
    }
  }

  class FactSet {
    List<Long> origin;
    List<String> facts;

    public FactSet(List<Long> origin, List<String> facts) {
      this.origin = origin;
      this.facts = facts;
    }

    // JSON cannot represent Long.MAX_VALUE so it is stored as null, fix the origin list
    public void fixOrigin() {
      for (int i = 0; i < this.origin.size(); i++) {
        if (this.origin.get(i) == null) {
          this.origin.set(i, Long.MAX_VALUE);
        }
      }
      Collections.sort(this.origin);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      FactSet factSet = (FactSet) o;

      if (!Objects.equals(origin, factSet.origin)) {
        return false;
      }
      return Objects.equals(facts, factSet.facts);
    }

    @Override
    public int hashCode() {
      int result = origin != null ? origin.hashCode() : 0;
      result = 31 * result + (facts != null ? facts.hashCode() : 0);
      return result;
    }

    @Override
    public String toString() {
      return "FactSet{" + "origin=" + origin + ", facts=" + facts + '}';
    }
  }

  class RuleSet implements Comparable<RuleSet> {
    Long origin;
    List<String> rules;

    public RuleSet(Long origin, List<String> rules) {
      this.origin = origin;
      this.rules = rules;
    }

    public void fixOrigin() {
      if (this.origin == null || this.origin == -1) {
        this.origin = Long.MAX_VALUE;
      }
    }

    @Override
    public int compareTo(RuleSet ruleSet) {
      // we only compare origin to sort the list of rulesets
      // there's only one of each origin so we don't need to compare the list of rules
      if (this.origin == null) {
        return -1;
      } else if (ruleSet.origin == null) {
        return 1;
      } else {
        return this.origin.compareTo(ruleSet.origin);
      }
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      RuleSet ruleSet = (RuleSet) o;

      if (!Objects.equals(origin, ruleSet.origin)) {
        return false;
      }
      return Objects.equals(rules, ruleSet.rules);
    }

    @Override
    public int hashCode() {
      int result = origin != null ? origin.hashCode() : 0;
      result = 31 * result + (rules != null ? rules.hashCode() : 0);
      return result;
    }

    @Override
    public String toString() {
      return "RuleSet{" + "origin=" + origin + ", rules=" + rules + '}';
    }
  }

  class CheckSet implements Comparable<CheckSet> {
    Long origin;
    List<String> checks;

    public CheckSet(Long origin, List<String> checks) {
      this.origin = origin;
      this.checks = checks;
    }

    public CheckSet(List<String> checks) {
      this.origin = null;
      this.checks = checks;
    }

    public void fixOrigin() {
      if (this.origin == null || this.origin == -1) {
        this.origin = Long.MAX_VALUE;
      }
    }

    @Override
    public int compareTo(CheckSet checkSet) {
      // we only compare origin to sort the list of checksets
      // there's only one of each origin so we don't need to compare the list of rules
      if (this.origin == null) {
        return -1;
      } else if (checkSet.origin == null) {
        return 1;
      } else {
        return this.origin.compareTo(checkSet.origin);
      }
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      CheckSet checkSet = (CheckSet) o;

      if (!Objects.equals(origin, checkSet.origin)) {
        return false;
      }
      return Objects.equals(checks, checkSet.checks);
    }

    @Override
    public int hashCode() {
      int result = origin != null ? origin.hashCode() : 0;
      result = 31 * result + (checks != null ? checks.hashCode() : 0);
      return result;
    }

    @Override
    public String toString() {
      return "CheckSet{" + "origin=" + origin + ", checks=" + checks + '}';
    }
  }
}
