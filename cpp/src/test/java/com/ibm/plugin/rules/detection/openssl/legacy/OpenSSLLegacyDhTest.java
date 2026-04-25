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
package com.ibm.plugin.rules.detection.openssl.legacy;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all 15 rule entries in {@link OpenSSLLegacyDh}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLLegacyDhTest extends TestBase {

    private static final String DH_OID = "1.2.840.113549.1.3.1";

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyDhTestFile.cc", this);
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

        switch (findingId) {
            case 0, 1, 2, 3, 4, 5, 6 -> {
                // DH_new, DH_generate_parameters_ex, DH_generate_key, DH_check,
                // DH_check_params_ex, DH_check_ex, DH_check_pub_key_ex
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("DH");
                assertDhPke(nodes);
            }
            case 7, 8 -> {
                // DH_compute_key, DH_compute_key_padded
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyAgreementContext.class);
                assertThat(value.asString()).isEqualTo("DH");
                assertDhKa(nodes);
            }
            case 9 -> {
                assertNamedGroupSkipped(detectionStore, value, nodes, "DH-1024-160");
            }
            case 10 -> {
                assertNamedGroupSkipped(detectionStore, value, nodes, "DH-2048-224");
            }
            case 11 -> {
                assertNamedGroupSkipped(detectionStore, value, nodes, "DH-2048-256");
            }
            case 12, 13, 14 -> {
                // DH_size, DH_bits, DH_security_bits
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("DH");
                assertDhPke(nodes);
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }

    private static void assertDhPke(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(DH.class);
        assertThat(n.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(n.asString()).isEqualTo("DH");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(DH_OID);
    }

    private static void assertDhKa(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(DH.class);
        assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(n.asString()).isEqualTo("DH");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(DH_OID);
    }

    private static void assertNamedGroupSkipped(
            DetectionStore<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
                    detectionStore,
            IValue<AstNode> value,
            List<INode> nodes,
            String expected) {
        // Translator has no case for "DH-1024-160" / "DH-2048-224" / "DH-2048-256" → empty nodes.
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(value.asString()).isEqualTo(expected);
        assertThat(nodes).isEmpty();
    }
}
