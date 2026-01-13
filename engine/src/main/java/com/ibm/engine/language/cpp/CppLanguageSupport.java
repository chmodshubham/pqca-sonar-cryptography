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
package com.ibm.engine.language.cpp;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.EnumMatcher;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IBaseMethodVisitorFactory;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.bytedeco.javacpp.BytePointer;
import org.bytedeco.javacpp.PointerPointer;
import org.bytedeco.llvm.clang.CXCursor;

public class CppLanguageSupport implements ILanguageSupport<Object, CXCursor, CXCursor, Object> {

    @Nonnull private final Handler<Object, CXCursor, CXCursor, Object> handler;

    public CppLanguageSupport() {
        this.handler = new Handler<>(this);
    }

    @Nonnull
    @Override
    public ILanguageTranslation<CXCursor> translation() {
        return new CppLanguageTranslation();
    }

    @Override
    public @Nonnull DetectionExecutive<Object, CXCursor, CXCursor, Object> createDetectionExecutive(
            @Nonnull CXCursor tree,
            @Nonnull IDetectionRule<CXCursor> detectionRule,
            @Nonnull IScanContext<Object, CXCursor> scanContext) {

        // Clang initialization
        // We need to parse the file specified in scanContext
        String filePath = scanContext.getFilePath();

        if (filePath == null || filePath.isEmpty()) {
            throw new IllegalArgumentException(
                    "File path is required for C++ analysis but was empty or null");
        }

        // Create Index
        // excludeDeclarationsFromPCH = 0, displayDiagnostics = 0
        org.bytedeco.llvm.clang.CXIndex index =
                org.bytedeco.llvm.global.clang.clang_createIndex(0, 0);

        org.bytedeco.llvm.clang.CXTranslationUnit unit = null;
        try {
            // Parse Translation Unit
            // source_filename = filePath
            // command_line_args = null (for now)
            // num_command_line_args = 0
            // unsaved_files = null
            // num_unsaved_files = 0
            // options = CXTranslationUnit_None
            unit =
                    org.bytedeco.llvm.global.clang.clang_parseTranslationUnit(
                            index,
                            new BytePointer(filePath),
                            (PointerPointer<?>) null,
                            0,
                            (org.bytedeco.llvm.clang.CXUnsavedFile) null,
                            0,
                            org.bytedeco.llvm.global.clang.CXTranslationUnit_None);

            if (unit == null) {
                throw new RuntimeException(
                        "Failed to parse translation unit for file: " + filePath);
            }

            // Get Cursor
            CXCursor cursor = org.bytedeco.llvm.global.clang.clang_getTranslationUnitCursor(unit);

            if (cursor == null || cursor.isNull()) {
                throw new RuntimeException(
                        "Failed to get translation unit cursor for file: " + filePath);
            }

            // Pass this real cursor to the executive
            // The tree argument passed to this method might be dummy from previous steps.
            // Ideally, we should use the one we just parsed.
            final org.bytedeco.llvm.clang.CXTranslationUnit finalUnit = unit;
            final org.bytedeco.llvm.clang.CXIndex finalIndex = index;

            return new DetectionExecutive<Object, CXCursor, CXCursor, Object>(
                    cursor, detectionRule, scanContext, this.handler) {
                @Override
                public void start() {
                    try {
                        super.start();
                    } finally {
                        // Cleanup
                        org.bytedeco.llvm.global.clang.clang_disposeTranslationUnit(finalUnit);
                        org.bytedeco.llvm.global.clang.clang_disposeIndex(finalIndex);
                    }
                }
            };
        } catch (Exception e) {
            // Ensure cleanup on error
            if (unit != null) {
                org.bytedeco.llvm.global.clang.clang_disposeTranslationUnit(unit);
            }
            org.bytedeco.llvm.global.clang.clang_disposeIndex(index);
            throw e;
        }
    }

    @Nonnull
    @Override
    public IDetectionEngine<CXCursor, CXCursor> createDetectionEngineInstance(
            @Nonnull DetectionStore<Object, CXCursor, CXCursor, Object> detectionStore) {
        return new CppDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<CXCursor, CXCursor> getBaseMethodVisitorFactory() {
        return CppBaseMethodVisitor::new;
    }

    @SuppressWarnings("null") // Eclipse null-safety checker limitation with Optional.empty()
    @Override
    public @Nonnull Optional<CXCursor> getEnclosingMethod(@Nonnull CXCursor expression) {
        // Placeholder traversal
        return Optional.<CXCursor>empty();
    }

    @Nullable @Override
    public MethodMatcher<CXCursor> createMethodMatcherBasedOn(@Nonnull CXCursor methodDefinition) {
        return null; // Placeholder
    }

    @Nullable @Override
    public EnumMatcher<CXCursor> createSimpleEnumMatcherFor(
            @Nonnull CXCursor enumIdentifier, @Nonnull MatchContext matchContext) {
        return null; // Placeholder
    }
}
