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
 * */
package com.ibm.plugin.rules.detection;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import org.bytedeco.llvm.clang.CXCursor;

/**
 * OpenSSL-specific detection rules for C++.
 *
 * <p>Migration note: Updated to use Clang/LLVM CXCursor instead of sonar-cxx AstNode.
 */
public final class CppOpenSslDetectionRules {

    private CppOpenSslDetectionRules() {
        // Utility class
    }

    @Nonnull
    public static List<IDetectionRule<CXCursor>> rules() {
        List<IDetectionRule<CXCursor>> detectionRules = new LinkedList<>();

        /*
         * 1. EVP_EncryptInit / EVP_EncryptInit_ex / EVP_EncryptInit_ex2
         *
         * int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
         *        const unsigned char *key, const unsigned char *iv);
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EVP_CIPHER_CTX")
                        .forMethods("EVP_EncryptInit", "EVP_EncryptInit_ex", "EVP_EncryptInit_ex2")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_EncryptInit"))
                        .withoutParameters()
                        .buildForContext(new CipherContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 1. EVP_DecryptInit / EVP_DecryptInit_ex / EVP_DecryptInit_ex2
         *
         * int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
         *        const unsigned char *key, const unsigned char *iv);
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EVP_CIPHER_CTX")
                        .forMethods("EVP_DecryptInit", "EVP_DecryptInit_ex", "EVP_DecryptInit_ex2")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_DecryptInit"))
                        .withoutParameters()
                        .buildForContext(new CipherContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 2. AES_set_encrypt_key
         *
         * int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
         *        AES_KEY *key);
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("AES_KEY")
                        .forMethods("AES_set_encrypt_key")
                        .shouldBeDetectedAs(new ValueActionFactory<>("AES_set_encrypt_key"))
                        .withoutParameters()
                        .buildForContext(new CipherContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 3. RSA_public_encrypt
         *
         * int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
         *        RSA *rsa, int padding);
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("RSA")
                        .forMethods("RSA_public_encrypt")
                        .shouldBeDetectedAs(new ValueActionFactory<>("RSA_public_encrypt"))
                        .withoutParameters()
                        .buildForContext(new CipherContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 4. EVP_DigestInit / EVP_DigestInit_ex / EVP_DigestInit_ex2
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EVP_MD_CTX")
                        .forMethods("EVP_DigestInit", "EVP_DigestInit_ex", "EVP_DigestInit_ex2")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_DigestInit"))
                        .withoutParameters()
                        .buildForContext(new DigestContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 5. HMAC_Init / HMAC_Init_ex
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("HMAC_CTX")
                        .forMethods("HMAC_Init", "HMAC_Init_ex")
                        .shouldBeDetectedAs(new ValueActionFactory<>("HMAC_Init"))
                        .withoutParameters()
                        .buildForContext(new MacContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 6. EVP_SignInit / EVP_VerifyInit
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EVP_MD_CTX")
                        .forMethods(
                                "EVP_SignInit",
                                "EVP_SignInit_ex",
                                "EVP_VerifyInit",
                                "EVP_VerifyInit_ex")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_SignInit"))
                        .withoutParameters()
                        .buildForContext(new SignatureContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 7. Key Generation: EVP_PKEY_keygen, RSA_generate_key, EVP_PKEY_Q_keygen
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EVP_PKEY_CTX")
                        .forMethods("EVP_PKEY_keygen")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_PKEY_keygen"))
                        .withoutParameters()
                        .buildForContext(new KeyContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("UNKNOWN")
                        .forMethods("EVP_PKEY_Q_keygen")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_PKEY_Q_keygen"))
                        .withoutParameters()
                        .buildForContext(new KeyContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("RSA")
                        .forMethods("RSA_generate_key", "RSA_generate_key_ex")
                        .shouldBeDetectedAs(new ValueActionFactory<>("RSA_generate_key"))
                        .withoutParameters()
                        .buildForContext(new KeyContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 8. Key Agreement: EVP_PKEY_derive
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EVP_PKEY_CTX")
                        .forMethods("EVP_PKEY_derive")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_PKEY_derive"))
                        .withoutParameters()
                        .buildForContext(new KeyAgreementContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 9. KDF: PKCS5_PBKDF2_HMAC
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("UNKNOWN") // Static function often called without object
                        .forMethods("PKCS5_PBKDF2_HMAC", "PKCS5_PBKDF2_HMAC_SHA1")
                        .shouldBeDetectedAs(new ValueActionFactory<>("PKCS5_PBKDF2_HMAC"))
                        .withoutParameters()
                        .buildForContext(new KeyDerivationFunctionContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 10. RNG: RAND_bytes
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("UNKNOWN") // Static function
                        .forMethods("RAND_bytes", "RAND_bytes_ex", "RAND_priv_bytes")
                        .shouldBeDetectedAs(new ValueActionFactory<>("RAND_bytes"))
                        .withoutParameters()
                        .buildForContext(new PRNGContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 11. SSL/TLS Context: SSL_CTX_new
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("SSL_CTX")
                        .forMethods("SSL_CTX_new")
                        .shouldBeDetectedAs(new ValueActionFactory<>("SSL_CTX_new"))
                        .withoutParameters()
                        .buildForContext(new ProtocolContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 17. Generic KDF: EVP_KDF_CTX_new
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EVP_KDF_CTX")
                        .forMethods("EVP_KDF_CTX_new")
                        .shouldBeDetectedAs(new ValueActionFactory<>("EVP_KDF_CTX_new"))
                        .withoutParameters()
                        .buildForContext(new KeyDerivationFunctionContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 18. CMAC: CMAC_Init
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("CMAC_CTX")
                        .forMethods("CMAC_Init")
                        .shouldBeDetectedAs(new ValueActionFactory<>("CMAC_Init"))
                        .withoutParameters()
                        .buildForContext(new MacContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        /*
         * 19. Legacy Key Generation: EC, DSA, DH
         */
        detectionRules.add(
                new DetectionRuleBuilder<CXCursor>()
                        .createDetectionRule()
                        .forObjectTypes("EC_KEY", "DSA", "DH")
                        .forMethods("EC_KEY_generate_key", "DSA_generate_key", "DH_generate_key")
                        .shouldBeDetectedAs(new ValueActionFactory<>("Legacy_Key_Validation"))
                        .withoutParameters()
                        .buildForContext(new KeyContext())
                        .inBundle(() -> "OpenSSL")
                        .withoutDependingDetectionRules());

        return detectionRules;
    }
}
