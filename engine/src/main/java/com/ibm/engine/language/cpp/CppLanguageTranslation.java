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

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.bytedeco.llvm.clang.CXCursor;

public class CppLanguageTranslation implements ILanguageTranslation<CXCursor> {

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull CXCursor methodInvocation) {
        return getName(methodInvocation);
    }

    @Nonnull
    @Override
    @SuppressWarnings("null") // Optional.empty() is never null
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CXCursor methodInvocation) {
        // Traverse children to find the member reference base
        final CXCursor[] baseObject = new CXCursor[1];
        org.bytedeco.llvm.global.clang.clang_visitChildren(
                methodInvocation,
                new org.bytedeco.llvm.clang.CXCursorVisitor() {
                    @Override
                    public int call(
                            CXCursor c,
                            CXCursor parent,
                            org.bytedeco.llvm.clang.CXClientData client_data) {
                        int kind = org.bytedeco.llvm.global.clang.clang_getCursorKind(c);
                        if (kind == org.bytedeco.llvm.global.clang.CXCursor_MemberRefExpr) {
                            // MemberRefExpr usually has the base as the first child
                            org.bytedeco.llvm.global.clang.clang_visitChildren(
                                    c,
                                    new org.bytedeco.llvm.clang.CXCursorVisitor() {
                                        @Override
                                        public int call(
                                                CXCursor base,
                                                CXCursor baseParent,
                                                org.bytedeco.llvm.clang.CXClientData data) {
                                            if (baseObject[0] == null) {
                                                baseObject[0] = base;
                                                return org.bytedeco.llvm.global.clang
                                                        .CXChildVisit_Break;
                                            }
                                            return org.bytedeco.llvm.global.clang
                                                    .CXChildVisit_Break;
                                        }
                                    },
                                    null);
                            return org.bytedeco.llvm.global.clang.CXChildVisit_Break;
                        }
                        return org.bytedeco.llvm.global.clang.CXChildVisit_Continue;
                    }
                },
                null);

        if (baseObject[0] != null) {
            org.bytedeco.llvm.clang.CXType type =
                    org.bytedeco.llvm.global.clang.clang_getCursorType(baseObject[0]);
            String typeName = getTypeString(type);
            if (typeName != null && !typeName.isEmpty()) {
                final String finalTypeName = typeName;
                return Optional.of(
                        target ->
                                finalTypeName.equals(target)
                                        || finalTypeName.endsWith("." + target)
                                        || target.endsWith("." + finalTypeName));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    @SuppressWarnings("null") // Optional.empty() is never null
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CXCursor methodInvocation) {
        org.bytedeco.llvm.clang.CXType type =
                org.bytedeco.llvm.global.clang.clang_getCursorType(methodInvocation);
        String typeName = getTypeString(type);
        if (typeName != null && !typeName.isEmpty()) {
            final String finalTypeName = typeName;
            return Optional.of(
                    target ->
                            finalTypeName.equals(target)
                                    || finalTypeName.endsWith("." + target)
                                    || target.endsWith("." + finalTypeName));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    @SuppressWarnings("null") // Collections.emptyList() is never null
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull CXCursor methodInvocation) {
        CXCursor definition =
                org.bytedeco.llvm.global.clang.clang_getCursorReferenced(methodInvocation);
        if (org.bytedeco.llvm.global.clang.clang_Cursor_isNull(definition) != 0) {
            return Collections.emptyList();
        }

        int numArgs = org.bytedeco.llvm.global.clang.clang_Cursor_getNumArguments(definition);
        java.util.List<IType> types = new java.util.ArrayList<>();
        for (int i = 0; i < numArgs; i++) {
            CXCursor arg = org.bytedeco.llvm.global.clang.clang_Cursor_getArgument(definition, i);
            org.bytedeco.llvm.clang.CXType type =
                    org.bytedeco.llvm.global.clang.clang_getCursorType(arg);
            String typeName = getTypeString(type);
            if (typeName != null && !typeName.isEmpty()) {
                final String finalTypeName = typeName;
                types.add(
                        target ->
                                finalTypeName.equals(target)
                                        || finalTypeName.endsWith("." + target)
                                        || target.endsWith("." + finalTypeName));
            }
        }
        return types;
    }

    private String getTypeString(org.bytedeco.llvm.clang.CXType type) {
        org.bytedeco.llvm.clang.CXString cxString =
                org.bytedeco.llvm.global.clang.clang_getTypeSpelling(type);
        String name = org.bytedeco.llvm.global.clang.clang_getCString(cxString).getString();
        org.bytedeco.llvm.global.clang.clang_disposeString(cxString);
        return name;
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull CXCursor identifierTree) {
        return getName(identifierTree);
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull CXCursor enumIdentifier) {
        return getName(enumIdentifier);
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull CXCursor enumClass) {
        return getName(enumClass);
    }

    @Nonnull
    @SuppressWarnings("null") // Optional.of() and Optional.empty() are never null
    private Optional<String> getName(CXCursor cursor) {
        org.bytedeco.llvm.clang.CXString cxString =
                org.bytedeco.llvm.global.clang.clang_getCursorSpelling(cursor);
        org.bytedeco.javacpp.BytePointer ptr =
                org.bytedeco.llvm.global.clang.clang_getCString(cxString);
        String name = ptr != null ? ptr.getString() : null;
        org.bytedeco.llvm.global.clang.clang_disposeString(cxString);
        return name != null && !name.isEmpty() ? Optional.of(name) : Optional.empty();
    }
}
