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
package com.ibm.plugin.rules.detection.openssl.ssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.protocol.TLS;
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
 * Covers all 42 rule entries in {@link OpenSSLLibssl}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}: detection-store structure +
 * translated INode tree (kind, asString, child walks).
 *
 * <p>Two finding shapes occur here:
 *
 * <ul>
 *   <li><b>Generic protocol</b> ({@link Protocol}): TLS, SSLv3.0, DTLS, QUIC, *-CIPHER-CONFIG,
 *       TLS-MIN-VERSION, TLS-MAX-VERSION — no children.
 *   <li><b>Versioned TLS</b> ({@link TLS}): TLSv1.0..1.3 (and 0RTT) — wraps a {@link Version}
 *       child carrying the parsed dotted version string.
 * </ul>
 */
class OpenSSLLibsslTest extends TestBase {

    private int findingCount = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslTestFile.cc", this);
        assertThat(findingCount).isEqualTo(42);
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
        /* Detection Store — common to every finding */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        // 40/42 findings are ValueAction; the 2 SSL_CTX_set_{min,max}_proto_version findings
        // emit OpenSSLVersionValue. Both implement IAction.
        assertThat(value).isInstanceOf(IAction.class);

        switch (findingId) {
            case 0, 1, 2 -> assertGenericProtocol(value, nodes, "TLS");
            case 3, 4, 5 -> assertVersionedTls(value, nodes, "TLSv1.3", "1.3");
            case 6, 7, 8 -> assertVersionedTls(value, nodes, "TLSv1.2", "1.2");
            case 9, 10, 11 -> assertVersionedTls(value, nodes, "TLSv1.1", "1.1");
            case 12, 13, 14 -> assertVersionedTls(value, nodes, "TLSv1.0", "1.0");
            case 15, 16, 17 -> assertGenericProtocol(value, nodes, "SSLv3.0");
            case 18, 19, 20 -> assertGenericProtocol(value, nodes, "DTLS");
            case 21, 22, 23 -> assertGenericProtocol(value, nodes, "DTLSv1.2");
            case 24, 25, 26 -> assertGenericProtocol(value, nodes, "DTLSv1.0");
            case 27, 28, 29 -> assertGenericProtocol(value, nodes, "QUIC");
            case 30 -> assertGenericProtocol(value, nodes, "TLS");
            case 31, 32 -> assertGenericProtocol(value, nodes, "TLS-CIPHER-CONFIG");
            case 33, 34 -> assertGenericProtocol(value, nodes, "TLS1.3-CIPHER-CONFIG");
            case 35 -> assertGenericProtocol(value, nodes, "TLS-MIN-VERSION");
            case 36 -> assertGenericProtocol(value, nodes, "TLS-MAX-VERSION");
            case 37, 38, 39 -> assertGenericProtocol(value, nodes, "TLS");
            case 40, 41 -> {
                // TLSv1.3-0RTT — translator recognises the "TLSv1.3" prefix and emits TLS(1.3).
                assertThat(value.asString()).isEqualTo("TLSv1.3-0RTT");
                assertTlsWithVersion(nodes, "TLSv1.3", "1.3");
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
        findingCount++;
    }

    private static void assertGenericProtocol(
            IValue<AstNode> value, List<INode> nodes, String expected) {
        assertThat(value.asString()).isEqualTo(expected);
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(Protocol.class);
        assertThat(node).isNotInstanceOf(TLS.class);
        assertThat(node.asString()).isEqualTo(expected);
        assertThat(node.hasChildren()).isFalse();
    }

    private static void assertVersionedTls(
            IValue<AstNode> value, List<INode> nodes, String expectedValue, String expectedVersion) {
        assertThat(value.asString()).isEqualTo(expectedValue);
        assertTlsWithVersion(nodes, expectedValue, expectedVersion);
    }

    private static void assertTlsWithVersion(
            List<INode> nodes, String expectedAsString, String expectedVersion) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(TLS.class);
        assertThat(node.asString()).isEqualTo(expectedAsString);
        INode version = node.getChildren().get(Version.class);
        assertThat(version).isNotNull();
        assertThat(version.asString()).isEqualTo(expectedVersion);
    }
}
