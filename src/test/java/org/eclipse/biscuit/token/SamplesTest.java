/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.token;

import static org.eclipse.biscuit.token.Block.fromBytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import biscuit.format.schema.Schema;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.vavr.Tuple2;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.eclipse.biscuit.crypto.KeyPair;
import org.eclipse.biscuit.crypto.PublicKey;
import org.eclipse.biscuit.datalog.RunLimits;
import org.eclipse.biscuit.datalog.SymbolTable;
import org.eclipse.biscuit.error.Error;
import org.eclipse.biscuit.error.Result;
import org.eclipse.biscuit.token.builder.Check;
import org.eclipse.biscuit.token.builder.parser.Parser;
import org.eclipse.biscuit.token.format.SignedBlock;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

class SamplesTest {
  final RunLimits runLimits = new RunLimits(500, 100, Duration.ofMillis(500));

  @TestFactory
  Stream<DynamicTest> jsonTest() throws Error.FormatError, IOException {
    Sample sample;
    try (InputStream inputStream =
        Thread.currentThread()
            .getContextClassLoader()
            .getResourceAsStream("samples/samples.json")) {
      sample =
          new ObjectMapper()
              .readValue(
                  new InputStreamReader(
                      new BufferedInputStream(Objects.requireNonNull(inputStream))),
                  Sample.class);
    }
    PublicKey publicKey =
        PublicKey.load(Schema.PublicKey.Algorithm.Ed25519, sample.root_public_key);
    KeyPair keyPair = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519, sample.root_private_key);
    return sample.testcases.stream().map(t -> processTestcase(t, publicKey, keyPair));
  }

  void compareBlocks(KeyPair root, List<Block> sampleBlocks, Biscuit token) throws Error {
    assertEquals(sampleBlocks.size(), 1 + token.blocks.size());
    Optional<Biscuit> sampleToken = Optional.empty();
    Biscuit b =
        compareBlock(root, sampleToken, 0, sampleBlocks.get(0), token.authority, token.symbolTable);
    sampleToken = Optional.of(b);

    for (int i = 0; i < token.blocks.size(); i++) {
      b =
          compareBlock(
              root,
              sampleToken,
              i + 1,
              sampleBlocks.get(i + 1),
              token.blocks.get(i),
              token.symbolTable);
      sampleToken = Optional.of(b);
    }
  }

  Biscuit compareBlock(
      KeyPair root,
      Optional<Biscuit> sampleToken,
      long sampleBlockIndex,
      Block sampleBlock,
      org.eclipse.biscuit.token.Block tokenBlock,
      SymbolTable tokenSymbols)
      throws Error {
    Optional<PublicKey> sampleExternalKey = sampleBlock.getExternalKey();
    List<PublicKey> samplePublicKeys = sampleBlock.getPublicKeys();
    String sampleDatalog = sampleBlock.getCode().replace("\"", "\\\"");
    var outputSample = Parser.datalog(sampleBlockIndex, sampleDatalog);

    // the invalid block rule with unbound variable cannot be parsed
    if (outputSample.isErr()) {
      return sampleToken.get();
    }

    Biscuit newSampleToken;
    if (sampleToken.isEmpty()) {
      org.eclipse.biscuit.token.builder.Biscuit builder =
          new org.eclipse.biscuit.token.builder.Biscuit(
              new SecureRandom(), root, Optional.empty(), outputSample.getOk());
      newSampleToken = builder.build();
    } else {
      Biscuit s = sampleToken.get();
      newSampleToken = s.attenuate(outputSample.getOk(), Schema.PublicKey.Algorithm.Ed25519);
    }

    org.eclipse.biscuit.token.Block generatedSampleBlock;
    if (sampleToken.isEmpty()) {
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

          for (Iterator<Map.Entry<String, JsonNode>> it = testCase.validations.fields();
              it.hasNext(); ) {
            var validationEntry = it.next();
            String validationName = validationEntry.getKey();
            ObjectNode validation = (ObjectNode) validationEntry.getValue();

            ObjectNode expectedResult = (ObjectNode) validation.get("result");
            String[] authorizerFacts = validation.get("authorizer_code").asText().split(";");

            Result<Long, Throwable> res;
            try {
              inputStream.read(data);
              Biscuit token = Biscuit.fromBytes(data, publicKey);
              assertArrayEquals(token.serialize(), data);

              List<org.eclipse.biscuit.token.Block> allBlocks = new ArrayList<>();
              allBlocks.add(token.authority);
              allBlocks.addAll(token.blocks);

              compareBlocks(privateKey, testCase.token, token);

              byte[] serBlockAuthority = token.authority.toBytes().getOk();
              System.out.println(Arrays.toString(serBlockAuthority));
              System.out.println(
                  Arrays.toString(token.serializedBiscuit.getAuthority().getBlock()));
              org.eclipse.biscuit.token.Block deserBlockAuthority =
                  fromBytes(serBlockAuthority, token.authority.getExternalKey()).getOk();
              assertEquals(
                  token.authority.print(token.symbolTable),
                  deserBlockAuthority.print(token.symbolTable));
              assert (Arrays.equals(
                  serBlockAuthority, token.serializedBiscuit.getAuthority().getBlock()));

              for (int i = 0; i < token.blocks.size() - 1; i++) {
                org.eclipse.biscuit.token.Block block = token.blocks.get(i);
                SignedBlock signedBlock = token.serializedBiscuit.getBlocks().get(i);
                byte[] serBlock = block.toBytes().getOk();
                org.eclipse.biscuit.token.Block deserBlock =
                    fromBytes(serBlock, block.getExternalKey()).getOk();
                assertEquals(block.print(token.symbolTable), deserBlock.print(token.symbolTable));
                assert (Arrays.equals(serBlock, signedBlock.getBlock()));
              }

              List<RevocationIdentifier> revocationIds = token.revocationIdentifiers();
              ArrayNode validationRevocationIds = (ArrayNode) validation.get("revocation_ids");
              assertEquals(revocationIds.size(), validationRevocationIds.size());
              for (int i = 0; i < revocationIds.size(); i++) {
                assertEquals(validationRevocationIds.get(i).asText(), revocationIds.get(i).toHex());
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

                if (validation.hasNonNull("world")) {
                  World world =
                      new ObjectMapper().treeToValue(validation.get("world"), World.class);

                  World authorizerWorld = new World(authorizer);
                  assertEquals(world.factMap(), authorizerWorld.factMap());
                  assertEquals(world.rules, authorizerWorld.rules);
                  assertEquals(world.checks, authorizerWorld.checks);
                  assertEquals(world.policies, authorizerWorld.policies);
                }

                res = Result.ok(authorizeResult);
              } catch (Exception e) {

                if (validation.hasNonNull("world")) {
                  World world =
                      new ObjectMapper().treeToValue(validation.get("world"), World.class);

                  World authorizerWorld = new World(authorizer);
                  assertEquals(world.factMap(), authorizerWorld.factMap());
                  assertEquals(world.rules, authorizerWorld.rules);
                  assertEquals(world.checks, authorizerWorld.checks);
                  assertEquals(world.policies, authorizerWorld.policies);
                }

                throw e;
              }
            } catch (Exception e) {
              res = Result.err(e);
            }

            if (expectedResult.has("Ok")) {
              if (res.isErr()) {
                System.out.println(
                    "validation '"
                        + validationName
                        + "' expected result Ok("
                        + expectedResult.get("Ok").asLong()
                        + "), got error");
                throw res.getErr();
              } else {
                assertEquals(expectedResult.get("Ok").asLong(), res.getOk());
              }
            } else {
              if (res.isErr()) {
                if (res.getErr() instanceof Error) {
                  Error e = (Error) res.getErr();
                  System.out.println("validation '" + validationName + "' got error: " + e);

                  // Serialize and deserialize the error to ensure the jackson node types match.
                  var objectMapper = new ObjectMapper();
                  var result = objectMapper.readTree(objectMapper.writeValueAsString(e.toJson()));
                  assertEquals(expectedResult.get("Err"), result);
                } else {
                  throw res.getErr();
                }
              } else {
                throw new Exception(
                    "validation '"
                        + validationName
                        + "' expected result error("
                        + expectedResult.get("Err")
                        + "), got success: "
                        + res.getOk());
              }
            }
          }
        });
  }

  static class Block {
    @JsonProperty List<String> symbols;
    @JsonProperty String code;

    @JsonProperty("public_keys")
    List<String> publicKeys;

    @JsonProperty("version")
    int version;

    @JsonProperty("external_key")
    String externalKey;

    public String getCode() {
      return code;
    }

    public List<PublicKey> getPublicKeys() {
      return this.publicKeys.stream()
          .map(pk -> Parser.publicKey(pk).getOk()._2)
          .collect(Collectors.toList());
    }

    public Optional<PublicKey> getExternalKey() {
      if (this.externalKey != null) {
        PublicKey externalKey = Parser.publicKey(this.externalKey).getOk()._2;
        return Optional.of(externalKey);
      } else {
        return Optional.empty();
      }
    }
  }

  static class TestCase {
    @JsonProperty String title;
    @JsonProperty String filename;
    @JsonProperty List<Block> token;
    @JsonProperty ObjectNode validations;
  }

  static class Sample {
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

  static class World {
    List<FactSet> facts;
    List<RuleSet> rules;
    List<CheckSet> checks;
    List<String> policies;

    public World(
        @JsonProperty("facts") List<FactSet> facts,
        @JsonProperty("rules") List<RuleSet> rules,
        @JsonProperty("checks") List<CheckSet> checks,
        @JsonProperty("policies") List<String> policies) {
      this.facts = facts;
      this.rules = rules.stream().sorted().collect(Collectors.toList());
      this.checks = checks.stream().sorted().collect(Collectors.toList());
      this.policies = policies;
    }

    public World(Authorizer authorizer) {
      this.facts =
          authorizer.getFacts().facts().entrySet().stream()
              .map(
                  entry ->
                      new FactSet(
                          entry.getKey().blockIds().stream()
                              .map(BigInteger::valueOf)
                              .sorted()
                              .collect(Collectors.toList()),
                          entry.getValue().stream()
                              .map(f -> authorizer.getSymbolTable().formatFact(f))
                              .sorted()
                              .collect(Collectors.toList())))
              .collect(Collectors.toList());

      var rules =
          authorizer.getRules().getRules().values().stream()
              .flatMap(Collection::stream)
              .collect(
                  Collectors.groupingBy(
                      t -> t._1,
                      Collectors.mapping(
                          t -> authorizer.getSymbolTable().formatRule(t._2), Collectors.toList())));

      this.rules =
          rules.entrySet().stream()
              .map(
                  entry ->
                      new RuleSet(
                          BigInteger.valueOf(entry.getKey()),
                          entry.getValue().stream().sorted().collect(Collectors.toList())))
              .sorted()
              .collect(Collectors.toList());

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
                      return new CheckSet(BigInteger.valueOf(t._1), checks1);
                    }
                  })
              .collect(Collectors.toList());
      this.policies =
          authorizer.getPolicies().stream().map(p -> p.toString()).collect(Collectors.toList());
      Collections.sort(this.rules);
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

  static class FactSet {
    List<Long> origin;
    List<String> facts;

    @JsonCreator
    public FactSet(
        @JsonProperty("origin") List<BigInteger> origin,
        @JsonProperty("facts") List<String> facts) {
      this.origin =
          origin.stream()
              .map(
                  v ->
                      v != null
                          ? v.min(BigInteger.valueOf(Long.MAX_VALUE)).longValue()
                          : Long.MAX_VALUE)
              .sorted()
              .collect(Collectors.toList());
      this.facts = facts;
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

  static class RuleSet implements Comparable<RuleSet> {
    public Long origin;
    public List<String> rules;

    @JsonCreator
    public RuleSet(
        @JsonProperty("origin") BigInteger origin, @JsonProperty("rules") List<String> rules) {
      this.origin = origin != null ? origin.longValue() : Long.MAX_VALUE;
      this.rules = rules;
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

  static class CheckSet implements Comparable<CheckSet> {
    Long origin;
    List<String> checks;

    @JsonCreator
    public CheckSet(
        @JsonProperty("origin") BigInteger origin, @JsonProperty("checks") List<String> checks) {
      this.origin =
          origin != null
              ? origin.min(BigInteger.valueOf(Long.MAX_VALUE)).longValue()
              : Long.MAX_VALUE;
      this.checks = checks;
    }

    public CheckSet(List<String> checks) {
      this.origin = null;
      this.checks = checks;
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
