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

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import org.bytedeco.llvm.clang.CXCursor;
import org.sonar.api.batch.fs.InputFile;

public class CppScanContext implements IScanContext<Object, CXCursor> {

    private final String filePath;

    public CppScanContext(String filePath) {
        this.filePath = filePath;
    }

    @Override
    public void reportIssue(
            @Nonnull Object currentRule, @Nonnull CXCursor tree, @Nonnull String message) {
        // TODO: Implement proper issue reporting mechanism
        // For now, log the issue to stderr
        System.err.println(
                String.format(
                        "[C++ Detection] Issue in %s: %s (cursor kind: %d)",
                        filePath,
                        message,
                        org.bytedeco.llvm.global.clang.clang_getCursorKind(tree)));
    }

    @Nonnull
    @Override
    public InputFile getInputFile() {
        // InputFile creation requires SonarQube's FileSystem API which is not available
        // in this standalone context. This method is typically called by SonarQube rules.
        throw new UnsupportedOperationException(
                "InputFile not available in CppScanContext. "
                        + "Use getFilePath() instead for file information.");
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return filePath != null ? filePath : "";
    }
}
