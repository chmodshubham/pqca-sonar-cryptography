/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection.openssl.keyagreement;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SecP256r1MLKEM768;
import com.ibm.mapper.model.algorithms.SecP384r1MLKEM1024;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X25519MLKEM768;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.algorithms.X448MLKEM1024;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all 31 rule entries in {@link OpenSSLEvpKeyAgreement}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 *
 * <p>{@code EVP_PKEY_CTX_new_id} call sites also fire {@link
 * com.ibm.plugin.rules.detection.openssl.keygen.OpenSSLEvpKeyGen} rules (KeyContext). This test
 * ignores those — verified in {@link com.ibm.plugin.rules.detection.openssl.keygen.OpenSSLEvpKeyGenTest}.
 *
 * <p>Per-value INode shape is dispatched through {@link #SHAPES}; each branch verifies node class,
 * kind, asString, and child structure (Oid, EllipticCurve, ParameterSetIdentifier).
 */
class OpenSSLEvpKeyAgreementTest extends TestBase {

    private final Map<String, Integer> keyAgreementCounts = new HashMap<>();

    @FunctionalInterface
    private interface ShapeAssertion {
        void check(List<INode> nodes);
    }

    private static final Map<String, ShapeAssertion> SHAPES = new HashMap<>();

    static {
        SHAPES.put("DH", nodes -> assertKaWithOid(nodes, DH.class, KeyAgreement.class, "DH",
                "1.2.840.113549.1.3.1"));
        SHAPES.put("DH-2048", nodes -> assertKaWithOid(nodes, DH.class, KeyAgreement.class, "DH",
                "1.2.840.113549.1.3.1"));
        SHAPES.put("DH-3072", nodes -> assertKaWithOid(nodes, DH.class, KeyAgreement.class, "DH",
                "1.2.840.113549.1.3.1"));
        SHAPES.put("DH-4096", nodes -> assertKaWithOid(nodes, DH.class, KeyAgreement.class, "DH",
                "1.2.840.113549.1.3.1"));
        SHAPES.put("ECDH", nodes -> assertKaWithOid(nodes, ECDH.class, KeyAgreement.class, "ECDH",
                "1.3.132.1.12"));
        SHAPES.put("ECDH-P256", nodes -> assertKaWithOid(nodes, ECDH.class, KeyAgreement.class,
                "ECDH", "1.3.132.1.12"));
        SHAPES.put("ECDH-P384", nodes -> assertKaWithOid(nodes, ECDH.class, KeyAgreement.class,
                "ECDH", "1.3.132.1.12"));
        SHAPES.put("ECDH-P521", nodes -> assertKaWithOid(nodes, ECDH.class, KeyAgreement.class,
                "ECDH", "1.3.132.1.12"));
        SHAPES.put("ECDH-SECP256K1", nodes -> assertKaWithOid(nodes, ECDH.class,
                KeyAgreement.class, "ECDH", "1.3.132.1.12"));
        SHAPES.put("ECDH-BRAINPOOLP256R1", nodes -> assertKaWithOid(nodes, ECDH.class,
                KeyAgreement.class, "ECDH", "1.3.132.1.12"));
        SHAPES.put("ECDH-BRAINPOOLP384R1", nodes -> assertKaWithOid(nodes, ECDH.class,
                KeyAgreement.class, "ECDH", "1.3.132.1.12"));
        SHAPES.put("ECDH-BRAINPOOLP512R1", nodes -> assertKaWithOid(nodes, ECDH.class,
                KeyAgreement.class, "ECDH", "1.3.132.1.12"));
        SHAPES.put("X25519", nodes -> assertEdwardsKa(nodes, X25519.class, "x25519",
                "Curve25519", "1.3.101.110"));
        SHAPES.put("X448", nodes -> assertEdwardsKa(nodes, X448.class, "x448",
                "Curve448", "1.3.101.111"));
        SHAPES.put("SM2", nodes -> {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(SM2.class);
            assertThat(n.getKind()).isEqualTo(Signature.class);
            assertThat(n.asString()).isEqualTo("SM2");
        });
        SHAPES.put("ML-KEM-512", nodes -> assertKemPset(nodes, MLKEM.class, "ML-KEM-512",
                "2.16.840.1.101.3.4.4.1", 512));
        SHAPES.put("ML-KEM-768", nodes -> assertKemPset(nodes, MLKEM.class, "ML-KEM-768",
                "2.16.840.1.101.3.4.4.2", 768));
        SHAPES.put("ML-KEM-1024", nodes -> assertKemPset(nodes, MLKEM.class, "ML-KEM-1024",
                "2.16.840.1.101.3.4.4.3", 1024));
        SHAPES.put("X25519MLKEM768", nodes -> assertHybridKem(nodes, X25519MLKEM768.class,
                "X25519MLKEM768"));
        SHAPES.put("X448MLKEM1024", nodes -> assertHybridKem(nodes, X448MLKEM1024.class,
                "X448MLKEM1024"));
        SHAPES.put("SecP256r1MLKEM768", nodes -> assertHybridKem(nodes, SecP256r1MLKEM768.class,
                "SecP256r1MLKEM768"));
        SHAPES.put("SecP384r1MLKEM1024", nodes -> assertHybridKem(nodes, SecP384r1MLKEM1024.class,
                "SecP384r1MLKEM1024"));
    }

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keyagreement/OpenSSLEvpKeyAgreementTestFile.cc", this);

        // After scan, assert every expected KeyAgreement rule fired.
        assertThat(keyAgreementCounts.getOrDefault("DH", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("DH-2048", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("DH-3072", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("DH-4096", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH-P256", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH-P384", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH-P521", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH-SECP256K1", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH-BRAINPOOLP256R1", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH-BRAINPOOLP384R1", 0)).isEqualTo(1);
        assertThat(keyAgreementCounts.getOrDefault("ECDH-BRAINPOOLP512R1", 0)).isEqualTo(1);
        // X25519 fires twice: derive (X25519_DERIVE) + CTX_new_id (X25519_CTX)
        assertThat(keyAgreementCounts.getOrDefault("X25519", 0)).isEqualTo(2);
        // Same for X448
        assertThat(keyAgreementCounts.getOrDefault("X448", 0)).isEqualTo(2);
        assertThat(keyAgreementCounts.getOrDefault("SM2", 0)).isEqualTo(1);
        // encaps + decaps each fire 7 → 2 per value
        assertThat(keyAgreementCounts.getOrDefault("ML-KEM-512", 0)).isEqualTo(2);
        assertThat(keyAgreementCounts.getOrDefault("ML-KEM-768", 0)).isEqualTo(2);
        assertThat(keyAgreementCounts.getOrDefault("ML-KEM-1024", 0)).isEqualTo(2);
        assertThat(keyAgreementCounts.getOrDefault("X25519MLKEM768", 0)).isEqualTo(2);
        assertThat(keyAgreementCounts.getOrDefault("X448MLKEM1024", 0)).isEqualTo(2);
        assertThat(keyAgreementCounts.getOrDefault("SecP256r1MLKEM768", 0)).isEqualTo(2);
        assertThat(keyAgreementCounts.getOrDefault("SecP384r1MLKEM1024", 0)).isEqualTo(2);

        int total = keyAgreementCounts.values().stream().mapToInt(Integer::intValue).sum();
        assertThat(total).isEqualTo(31);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);

        if (detectionStore.getDetectionValueContext() instanceof KeyAgreementContext) {
            String key = value.asString();
            keyAgreementCounts.merge(key, 1, Integer::sum);
            assertThat(nodes).hasSize(1);
            ShapeAssertion shape = SHAPES.get(key);
            assertThat(shape).as("Missing shape mapping for KA value: " + key).isNotNull();
            shape.check(nodes);
        } else if (detectionStore.getDetectionValueContext() instanceof KeyContext) {
            // Expected: KeyGen rules fire on the same EVP_PKEY_CTX_new_id call sites.
            // Verified in OpenSSLEvpKeyGenTest. KeyContext findings here may emit any of:
            // RSA / RSA-PSS / DSA / EC / DH / ED25519 / ED448 / X25519 / X448.
            assertKeyContextShape(value, nodes);
        } else {
            throw new AssertionError(
                    "Unexpected context: "
                            + detectionStore.getDetectionValueContext().getClass().getSimpleName());
        }
    }

    /* ============================ helpers ============================ */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertKaWithOid(
            List<INode> nodes,
            Class<? extends INode> klass,
            Class<?> kind,
            String asString,
            String oid) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(kind);
        assertThat(n.asString()).isEqualTo(asString);
        INode oidNode = n.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo(oid);
    }

    private static void assertEdwardsKa(
            List<INode> nodes,
            Class<? extends INode> klass,
            String asString,
            String curveName,
            String oid) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode curve = n.getChildren().get(EllipticCurve.class);
        assertThat(curve).isNotNull();
        assertThat(curve.asString()).isEqualTo(curveName);
        INode oidNode = n.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo(oid);
    }

    private static void assertKemPset(
            List<INode> nodes,
            Class<? extends INode> klass,
            String asString,
            String oid,
            int pset) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(KeyEncapsulationMechanism.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode oidNode = n.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo(oid);
        INode psetNode = n.getChildren().get(ParameterSetIdentifier.class);
        assertThat(psetNode).isNotNull();
        assertThat(psetNode.asString()).isEqualTo(Integer.toString(pset));
    }

    private static void assertHybridKem(
            List<INode> nodes, Class<? extends INode> klass, String asString) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(KeyEncapsulationMechanism.class);
        assertThat(n.asString()).isEqualTo(asString);
    }

    /**
     * KeyContext findings are emitted alongside KA findings by EVP_PKEY_CTX_new_id calls. They
     * cover RSA, DSA, EC (→ ECDSA), DH, ED25519, ED448, X25519, X448. Each maps to a known
     * algorithm node — verify shape cheaply.
     */
    private static void assertKeyContextShape(IValue<AstNode> value, List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        switch (value.asString()) {
            case "RSA", "RSA-PSS" -> {
                assertThat(n).isInstanceOf(RSA.class);
                assertThat(n.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(n.asString()).isEqualTo("RSA");
            }
            case "DSA" -> {
                assertThat(n).isInstanceOf(DSA.class);
                assertThat(n.getKind()).isEqualTo(Signature.class);
            }
            case "EC" -> {
                assertThat(n).isInstanceOf(ECDSA.class);
                assertThat(n.getKind()).isEqualTo(Signature.class);
            }
            case "DH" -> {
                assertThat(n).isInstanceOf(DH.class);
                assertThat(n.getKind()).isEqualTo(PublicKeyEncryption.class);
            }
            case "ED25519" -> {
                assertThat(n).isInstanceOf(Ed25519.class);
                assertThat(n.getKind()).isEqualTo(Signature.class);
            }
            case "ED448" -> {
                assertThat(n).isInstanceOf(Ed448.class);
                assertThat(n.getKind()).isEqualTo(Signature.class);
            }
            case "X25519" -> {
                assertThat(n).isInstanceOf(X25519.class);
                assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
            }
            case "X448" -> {
                assertThat(n).isInstanceOf(X448.class);
                assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
            }
            default -> throw new AssertionError(
                    "Unexpected KeyContext value: " + value.asString());
        }
    }
}
