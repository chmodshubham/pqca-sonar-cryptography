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
package com.ibm.engine.language.cpp;

import com.ibm.engine.detection.IBaseMethodVisitor;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.TraceSymbol;
import javax.annotation.Nonnull;
import org.bytedeco.llvm.clang.CXCursor;

public class CppBaseMethodVisitor implements IBaseMethodVisitor<CXCursor> {

    @Nonnull private final IDetectionEngine<CXCursor, CXCursor> detectionEngine;
    @Nonnull private final TraceSymbol<CXCursor> traceSymbol;

    public CppBaseMethodVisitor(
            @Nonnull TraceSymbol<CXCursor> traceSymbol,
            @Nonnull IDetectionEngine<CXCursor, CXCursor> detectionEngine) {
        this.traceSymbol = traceSymbol;
        this.detectionEngine = detectionEngine;
    }

    @Override
    public void visitMethodDefinition(@Nonnull CXCursor method) {
        org.bytedeco.llvm.global.clang.clang_visitChildren(
                method,
                new org.bytedeco.llvm.clang.CXCursorVisitor() {
                    @Override
                    public int call(
                            CXCursor c,
                            CXCursor parent,
                            org.bytedeco.llvm.clang.CXClientData client_data) {
                        if (c != null && !c.isNull()) {
                            detectionEngine.run(traceSymbol, c);
                        }
                        return org.bytedeco.llvm.global.clang.CXChildVisit_Recurse;
                    }
                },
                null);
    }
}
