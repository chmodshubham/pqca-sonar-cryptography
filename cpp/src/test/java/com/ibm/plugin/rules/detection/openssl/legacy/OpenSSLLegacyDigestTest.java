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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RIPEMD;
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
 * Covers all 28 rule entries in {@link OpenSSLLegacyDigest}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 *
 * <p>Note: legacy rules emit dash-less values like {@code "SHA1"}, {@code "SHA224"} etc. The digest
 * translator expects dashed variants ({@code "SHA-1"}, {@code "SHA-224"}, …) and therefore yields
 * empty nodes for all SHA-family entries. Only {@code "MD5"} and {@code "RIPEMD160"} match
 * translator cases directly.
 */
class OpenSSLLegacyDigestTest extends TestBase {

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyDigestTestFile.cc", this);
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);

        switch (findingId) {
            case 0, 1, 2, 3 -> {
                assertThat(value.asString()).isEqualTo("MD5");
                assertMd5(nodes);
            }
            case 4, 5, 6, 7 -> assertEmpty(value, "SHA1", nodes);
            case 8, 9, 10, 11 -> assertEmpty(value, "SHA224", nodes);
            case 12, 13, 14, 15 -> assertEmpty(value, "SHA256", nodes);
            case 16, 17, 18, 19 -> assertEmpty(value, "SHA384", nodes);
            case 20, 21, 22, 23 -> assertEmpty(value, "SHA512", nodes);
            case 24, 25, 26, 27 -> {
                assertThat(value.asString()).isEqualTo("RIPEMD160");
                assertRipemd160(nodes);
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }

    private static void assertEmpty(IValue<AstNode> value, String expected, List<INode> nodes) {
        assertThat(value.asString()).isEqualTo(expected);
        assertThat(nodes).isEmpty();
    }

    private static void assertMd5(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(MD5.class);
        assertThat(n.getKind()).isEqualTo(MessageDigest.class);
        assertThat(n.asString()).isEqualTo("MD5");
        INode size = n.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo("128");
        INode bs = n.getChildren().get(BlockSize.class);
        assertThat(bs).isNotNull();
        assertThat(bs.asString()).isEqualTo("512");
    }

    private static void assertRipemd160(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(RIPEMD.class);
        assertThat(n.getKind()).isEqualTo(MessageDigest.class);
        assertThat(n.asString()).isEqualTo("RIPEMD-160");
        INode size = n.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo("160");
    }
}
