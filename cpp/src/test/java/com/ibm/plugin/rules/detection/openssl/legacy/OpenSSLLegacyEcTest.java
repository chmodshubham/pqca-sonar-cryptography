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
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
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
 * Covers all 20 rule entries in {@link OpenSSLLegacyEc}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLLegacyEcTest extends TestBase {

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyEcTestFile.cc", this);
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
            case 0, 1, 2, 3, 4, 5 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("EC");
                assertEcdsa(nodes);
            }
            case 6, 8, 10, 11, 12 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertThat(value.asString()).isEqualTo("ECDSA-SIGN");
                assertEcdsa(nodes);
            }
            case 7, 9 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertThat(value.asString()).isEqualTo("ECDSA-VERIFY");
                assertEcdsa(nodes);
            }
            case 13 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertThat(value.asString()).isEqualTo("ECDSA");
                assertThat(nodes).isEmpty();
            }
            case 14 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyAgreementContext.class);
                assertThat(value.asString()).isEqualTo("ECDH");
                assertEcdh(nodes);
            }
            case 15 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("EC");
                assertEcdsa(nodes);
            }
            case 16 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("EC-GFP");
                assertThat(nodes).isEmpty();
            }
            case 17 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("EC-GF2M");
                assertThat(nodes).isEmpty();
            }
            case 18, 19 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("EC");
                assertEcdsa(nodes);
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }

    private static void assertEcdsa(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(ECDSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo("ECDSA");
    }

    private static void assertEcdh(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(ECDH.class);
        assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(n.asString()).isEqualTo("ECDH");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.3.132.1.12");
    }
}
