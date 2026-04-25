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
package com.ibm.plugin.rules.detection.openssl.kdf;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.PBKDF1;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.Scrypt;
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
 * Covers all 45 rule entries in {@link OpenSSLEvpKdf}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLEvpKdfTest extends TestBase {

    private int findingCount = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfTestFile.cc", this);
        assertThat(findingCount).isEqualTo(45);
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
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(ValueAction.class);

        switch (findingId) {
            case 0 -> {
                assertThat(value.asString()).isEqualTo("PBKDF2-HMAC-SHA1");
                assertPbkdf2WithSha(nodes, SHA.class, "SHA1", 160);
            }
            case 1 -> {
                assertThat(value.asString()).isEqualTo("PBKDF2-HMAC-SHA256");
                assertPbkdf2WithSha2(nodes, 256);
            }
            case 2 -> {
                assertThat(value.asString()).isEqualTo("PBKDF2-HMAC-SHA384");
                assertPbkdf2WithSha2(nodes, 384);
            }
            case 3 -> {
                assertThat(value.asString()).isEqualTo("PBKDF2-HMAC-SHA512");
                assertPbkdf2WithSha2(nodes, 512);
            }
            case 4 -> {
                assertThat(value.asString()).isEqualTo("HKDF-SHA1");
                assertHkdfWithSha(nodes, SHA.class, "HKDF-SHA1", 160);
            }
            case 5 -> {
                assertThat(value.asString()).isEqualTo("HKDF-SHA256");
                assertHkdfWithSha2(nodes, 256, "HKDF-SHA256");
            }
            case 6 -> {
                assertThat(value.asString()).isEqualTo("HKDF-SHA384");
                assertHkdfWithSha2(nodes, 384, "HKDF-SHA384");
            }
            case 7 -> {
                assertThat(value.asString()).isEqualTo("HKDF-SHA512");
                assertHkdfWithSha2(nodes, 512, "HKDF-SHA512");
            }
            case 8 -> {
                assertThat(value.asString()).isEqualTo("HKDF-SHA3-256");
                assertHkdfWithSha(nodes, SHA3.class, "HKDF-SHA3-256", 256);
            }
            case 9 -> {
                assertThat(value.asString()).isEqualTo("SCRYPT");
                assertSimpleAlgo(nodes, Scrypt.class, "SCRYPT");
            }
            case 10, 11, 12, 13 -> {
                assertThat(value.asString()).startsWith("TLS1-PRF-");
                // TLS1-PRF-* maps to bare PBKDF2 (no digest child)
                assertSimpleAlgo(nodes, PBKDF2.class, "PBKDF2");
            }
            case 14 -> {
                assertThat(value.asString()).isEqualTo("TLS13-KDF-SHA256");
                assertHkdfWithSha2(nodes, 256, "HKDF-SHA256");
            }
            case 15 -> {
                assertThat(value.asString()).isEqualTo("TLS13-KDF-SHA384");
                assertHkdfWithSha2(nodes, 384, "HKDF-SHA384");
            }
            case 16 -> {
                assertThat(value.asString()).isEqualTo("TLS13-KDF-SHA512");
                assertHkdfWithSha2(nodes, 512, "HKDF-SHA512");
            }
            case 17 -> {
                assertThat(value.asString()).isEqualTo("X963KDF-SHA1");
                assertX963WithSha(nodes, SHA.class, 160);
            }
            case 18 -> {
                assertThat(value.asString()).isEqualTo("X963KDF-SHA224");
                assertX963WithSha2(nodes, 224);
            }
            case 19 -> {
                assertThat(value.asString()).isEqualTo("X963KDF-SHA256");
                assertX963WithSha2(nodes, 256);
            }
            case 20 -> {
                assertThat(value.asString()).isEqualTo("X963KDF-SHA384");
                assertX963WithSha2(nodes, 384);
            }
            case 21 -> {
                assertThat(value.asString()).isEqualTo("X963KDF-SHA512");
                assertX963WithSha2(nodes, 512);
            }
            case 22 -> {
                assertThat(value.asString()).isEqualTo("KBKDF-HMAC-SHA1");
                assertKbkdfHmac(nodes, SHA.class, "HMAC-SHA1", 160);
            }
            case 23 -> {
                assertThat(value.asString()).isEqualTo("KBKDF-HMAC-SHA256");
                assertKbkdfHmacSha2(nodes, 256);
            }
            case 24 -> {
                assertThat(value.asString()).isEqualTo("KBKDF-HMAC-SHA384");
                assertKbkdfHmacSha2(nodes, 384);
            }
            case 25 -> {
                assertThat(value.asString()).isEqualTo("KBKDF-HMAC-SHA512");
                assertKbkdfHmacSha2(nodes, 512);
            }
            case 26 -> {
                assertThat(value.asString()).isEqualTo("KBKDF-CMAC-AES128");
                assertKbkdfCmacAes(nodes, 128);
            }
            case 27 -> {
                assertThat(value.asString()).isEqualTo("KBKDF-CMAC-AES256");
                assertKbkdfCmacAes(nodes, 256);
            }
            case 28, 29, 30 -> {
                assertThat(value.asString()).startsWith("X942KDF");
                assertSimpleAlgo(nodes, ANSIX942.class, "ANSI X9.42");
            }
            case 31 -> {
                assertThat(value.asString()).isEqualTo("SSKDF");
                assertSimpleAlgo(nodes, ConcatenationKDF.class, "ConcatenationKDF");
            }
            case 32, 33 -> {
                assertThat(value.asString()).startsWith("SSHKDF-");
                assertSimpleAlgo(nodes, PBKDF2.class, "PBKDF2");
            }
            case 34 -> {
                assertThat(value.asString()).isEqualTo("KRB5KDF");
                assertGenericKdf(nodes, "KRB5KDF", KeyDerivationFunction.class);
            }
            case 35 -> {
                assertThat(value.asString()).isEqualTo("ARGON2D");
                assertGenericKdf(nodes, "Argon2d", PasswordBasedKeyDerivationFunction.class);
            }
            case 36 -> {
                assertThat(value.asString()).isEqualTo("ARGON2I");
                assertGenericKdf(nodes, "Argon2i", PasswordBasedKeyDerivationFunction.class);
            }
            case 37 -> {
                assertThat(value.asString()).isEqualTo("ARGON2ID");
                assertGenericKdf(nodes, "Argon2id", PasswordBasedKeyDerivationFunction.class);
            }
            case 38 -> {
                assertThat(value.asString()).isEqualTo("PKCS12KDF");
                assertGenericKdf(nodes, "PKCS12KDF", PasswordBasedKeyDerivationFunction.class);
            }
            case 39 -> {
                assertThat(value.asString()).isEqualTo("PVKKDF");
                assertGenericKdf(nodes, "PVKKDF", PasswordBasedKeyDerivationFunction.class);
            }
            case 40 -> {
                assertThat(value.asString()).isEqualTo("HMAC-DRBG-KDF");
                assertGenericKdf(nodes, "HMAC-DRBG-KDF", KeyDerivationFunction.class);
            }
            case 41 -> {
                assertThat(value.asString()).isEqualTo("PBKDF1-MD5");
                assertPbkdf1(nodes, MD5.class, "PBKDF1-MD5", 128);
            }
            case 42 -> {
                assertThat(value.asString()).isEqualTo("PBKDF1-SHA1");
                assertPbkdf1(nodes, SHA.class, "PBKDF1-SHA1", 160);
            }
            case 43 -> {
                assertThat(value.asString()).isEqualTo("PBKDF2-HMAC");
                assertSimpleAlgo(nodes, PBKDF2.class, "PBKDF2");
            }
            case 44 -> {
                assertThat(value.asString()).isEqualTo("PBKDF2-HMAC-SHA1");
                assertPbkdf2WithSha(nodes, SHA.class, "SHA1", 160);
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
        findingCount++;
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertSimpleAlgo(
            List<INode> nodes, Class<? extends INode> klass, String asString) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.asString()).isEqualTo(asString);
    }

    private static void assertGenericKdf(
            List<INode> nodes, String asString, Class<?> kindClass) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(Algorithm.class);
        assertThat(n.getKind()).isEqualTo(kindClass);
        assertThat(n.asString()).isEqualTo(asString);
    }

    private static void assertPbkdf2WithSha(
            List<INode> nodes, Class<? extends INode> shaClass, String shaName, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(PBKDF2.class);
        assertThat(n.asString()).isEqualTo("PBKDF2-" + shaName);
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        assertThat(digest.asString()).isEqualTo(shaName);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertPbkdf2WithSha2(List<INode> nodes, int digestSize) {
        assertPbkdf2WithSha(nodes, SHA2.class, "SHA" + digestSize, digestSize);
    }

    private static void assertHkdfWithSha(
            List<INode> nodes, Class<? extends INode> shaClass, String asString, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(HKDF.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertHkdfWithSha2(List<INode> nodes, int digestSize, String asString) {
        assertHkdfWithSha(nodes, SHA2.class, asString, digestSize);
    }

    private static void assertX963WithSha(
            List<INode> nodes, Class<? extends INode> shaClass, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(ANSIX963.class);
        assertThat(n.asString()).isEqualTo("ANSI X9.63");
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertX963WithSha2(List<INode> nodes, int digestSize) {
        assertX963WithSha(nodes, SHA2.class, digestSize);
    }

    private static void assertKbkdfHmac(
            List<INode> nodes,
            Class<? extends INode> shaClass,
            String hmacAsString,
            int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(KDFCounter.class);
        assertThat(n.asString()).isEqualTo("KDF in Counter Mode");
        INode mac = n.getChildren().get(Mac.class);
        assertThat(mac).isNotNull().isInstanceOf(HMAC.class);
        assertThat(mac.asString()).isEqualTo(hmacAsString);
        INode digest = mac.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertKbkdfHmacSha2(List<INode> nodes, int digestSize) {
        assertKbkdfHmac(nodes, SHA2.class, "HMAC-SHA" + digestSize, digestSize);
    }

    private static void assertKbkdfCmacAes(List<INode> nodes, int keyLength) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(KDFCounter.class);
        assertThat(n.asString()).isEqualTo("KDF in Counter Mode");
        INode mac = n.getChildren().get(Mac.class);
        assertThat(mac).isNotNull().isInstanceOf(CMAC.class);
        assertThat(mac.asString()).isEqualTo("AES-CMAC");
        INode aes = mac.getChildren().get(BlockCipher.class);
        assertThat(aes).isNotNull().isInstanceOf(AES.class);
        assertThat(aes.asString()).isEqualTo("AES" + keyLength);
        INode keyLen = aes.getChildren().get(KeyLength.class);
        assertThat(keyLen).isNotNull();
        assertThat(keyLen.asString()).isEqualTo(Integer.toString(keyLength));
    }

    private static void assertPbkdf1(
            List<INode> nodes, Class<? extends INode> digestClass, String asString, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(PBKDF1.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(digestClass);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }
}
