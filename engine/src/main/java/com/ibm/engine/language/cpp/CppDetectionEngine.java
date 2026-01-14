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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.Parameter;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.bytedeco.llvm.clang.CXCursor;

public class CppDetectionEngine implements IDetectionEngine<CXCursor, CXCursor> {

    @Nonnull
    @SuppressWarnings("unused")
    private final DetectionStore<Object, CXCursor, CXCursor, Object> detectionStore;

    @Nonnull
    @SuppressWarnings("unused")
    private final Handler<Object, CXCursor, CXCursor, Object> handler;

    public CppDetectionEngine(
            @Nonnull DetectionStore<Object, CXCursor, CXCursor, Object> detectionStore,
            @Nonnull Handler<Object, CXCursor, CXCursor, Object> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull CXCursor tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<CXCursor> traceSymbol, @Nonnull CXCursor tree) {
        // Placeholder implementation using Clang cursor
    }

    @Nullable @Override
    public CXCursor extractArgumentFromMethodCaller(
            @Nonnull CXCursor methodDefinition,
            @Nonnull CXCursor methodInvocation,
            @Nonnull CXCursor methodParameterIdentifier) {

        int numArgsDef =
                org.bytedeco.llvm.global.clang.clang_Cursor_getNumArguments(methodDefinition);
        int targetIndex = -1;

        for (int i = 0; i < numArgsDef; i++) {
            CXCursor arg =
                    org.bytedeco.llvm.global.clang.clang_Cursor_getArgument(methodDefinition, i);
            if (org.bytedeco.llvm.global.clang.clang_equalCursors(arg, methodParameterIdentifier)
                    != 0) {
                targetIndex = i;
                break;
            }
        }

        if (targetIndex != -1) {
            int numArgsInv =
                    org.bytedeco.llvm.global.clang.clang_Cursor_getNumArguments(methodInvocation);
            if (targetIndex < numArgsInv) {
                return org.bytedeco.llvm.global.clang.clang_Cursor_getArgument(
                        methodInvocation, targetIndex);
            }
        }

        return null;
    }

    @Nonnull
    @Override
    @SuppressWarnings({"unchecked", "null"})
    public <O> List<ResolvedValue<O, CXCursor>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull CXCursor expression,
            @Nullable IValueFactory<CXCursor> valueFactory) {
        int kind = org.bytedeco.llvm.global.clang.clang_getCursorKind(expression);
        if (kind == org.bytedeco.llvm.global.clang.CXCursor_StringLiteral) {
            String val = getName(expression);
            if (val.startsWith("\"") && val.endsWith("\"")) {
                val = val.substring(1, val.length() - 1);
            }
            if (clazz.isAssignableFrom(String.class)) {
                return List.of(new ResolvedValue<>((O) val, expression));
            }
        }
        return Collections.emptyList();
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull CXCursor expression, @Nonnull Parameter<CXCursor> parameter) {
        // Placeholder
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull CXCursor methodDefinition,
            @Nonnull Parameter<CXCursor> parameter) {
        // Placeholder
    }

    @Nullable @Override
    @SuppressWarnings({"unchecked", "null"})
    public <O> ResolvedValue<O, CXCursor> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull CXCursor enumClassDefinition,
            @Nonnull LinkedList<CXCursor> selections) {

        if (selections.isEmpty()) {
            return null;
        }

        // Use the last selection as the target enum value name
        CXCursor targetSelection = selections.getLast();
        String targetName = getName(targetSelection);

        if (targetName == null) {
            return null;
        }

        // Search for the enum constant in the enum class definition
        final CXCursor[] found = new CXCursor[1];

        org.bytedeco.llvm.global.clang.clang_visitChildren(
                enumClassDefinition,
                new org.bytedeco.llvm.clang.CXCursorVisitor() {
                    @Override
                    public int call(
                            CXCursor c,
                            CXCursor parent,
                            org.bytedeco.llvm.clang.CXClientData client_data) {
                        if (org.bytedeco.llvm.global.clang.clang_getCursorKind(c)
                                == org.bytedeco.llvm.global.clang.CXCursor_EnumConstantDecl) {
                            String name = getName(c);
                            if (targetName.equals(name)) {
                                found[0] = c;
                                return org.bytedeco.llvm.global.clang.CXChildVisit_Break;
                            }
                        }
                        return org.bytedeco.llvm.global.clang.CXChildVisit_Continue;
                    }
                },
                null);

        if (found[0] != null) {
            // Found it.
            // In a real implementation we might need to map the value to type O.
            // For now, we return a resolved value wrapping the cursor.
            // We need a way to construct ResolvedValue.
            // Assuming ResolvedValue has a constructor taking (O value, CXCursor tree)
            // But O is generic.
            // If the rule expects a String, we can pass the name.
            if (clazz.equals(String.class)) {
                return new ResolvedValue<>((O) targetName, found[0]);
            }
            // Or maybe just generic object?
        }

        return null;
    }

    private String getName(CXCursor cursor) {
        org.bytedeco.llvm.clang.CXString cxString =
                org.bytedeco.llvm.global.clang.clang_getCursorSpelling(cursor);
        org.bytedeco.javacpp.BytePointer ptr =
                org.bytedeco.llvm.global.clang.clang_getCString(cxString);
        String name = ptr != null ? ptr.getString() : null;
        org.bytedeco.llvm.global.clang.clang_disposeString(cxString);
        return name;
    }

    @Nonnull
    @Override
    @SuppressWarnings("null")
    public Optional<TraceSymbol<CXCursor>> getAssignedSymbol(@Nonnull CXCursor expression) {
        int kind = org.bytedeco.llvm.global.clang.clang_getCursorKind(expression);
        if (kind == org.bytedeco.llvm.global.clang.CXCursor_VarDecl) {
            return Optional.of(TraceSymbol.createFrom(expression));
        } else if (kind == org.bytedeco.llvm.global.clang.CXCursor_BinaryOperator) {
            // Check if it is an assignment.
            // This is slightly heuristic without checking tokens, but usually BinaryOperator in
            // this parameter position implies we are looking for assignment
            // We can try to get the operator.
            // For now, let's look at LHS.
            final CXCursor[] lhs = new CXCursor[1];
            org.bytedeco.llvm.global.clang.clang_visitChildren(
                    expression,
                    new org.bytedeco.llvm.clang.CXCursorVisitor() {
                        @Override
                        public int call(
                                CXCursor c,
                                CXCursor parent,
                                org.bytedeco.llvm.clang.CXClientData client_data) {
                            if (lhs[0] == null) {
                                lhs[0] = c;
                                return org.bytedeco.llvm.global.clang.CXChildVisit_Break;
                            }
                            return org.bytedeco.llvm.global.clang.CXChildVisit_Break;
                        }
                    },
                    null);

            if (lhs[0] != null) {
                // ideally we should check if op is '='
                return Optional.of(TraceSymbol.createFrom(lhs[0]));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    @SuppressWarnings("null")
    public Optional<TraceSymbol<CXCursor>> getMethodInvocationParameterSymbol(
            @Nonnull CXCursor methodInvocation, @Nonnull Parameter<CXCursor> parameter) {

        int index = parameter.getIndex();
        int numArgs = org.bytedeco.llvm.global.clang.clang_Cursor_getNumArguments(methodInvocation);

        if (index >= 0 && index < numArgs) {
            CXCursor arg =
                    org.bytedeco.llvm.global.clang.clang_Cursor_getArgument(
                            methodInvocation, index);
            // Create a TraceSymbol for this argument
            // We need a proper creation method, but assuming createStart or similar for now or just
            // wrapping it
            // TraceSymbol usually represents a variable or value.
            // If arg is a variable reference, we might want that.
            // For now return a symbol wrapping the cursor.
            return Optional.of(TraceSymbol.createFrom(arg));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    @SuppressWarnings("null")
    public Optional<TraceSymbol<CXCursor>> getNewClassParameterSymbol(
            @Nonnull CXCursor newClass, @Nonnull Parameter<CXCursor> parameter) {
        return Optional.empty(); // Placeholder
    }

    @Override
    public boolean isInvocationOnVariable(
            CXCursor methodInvocation, @Nonnull TraceSymbol<CXCursor> variableSymbol) {
        final boolean[] result = new boolean[1];
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
                            org.bytedeco.llvm.global.clang.clang_visitChildren(
                                    c,
                                    new org.bytedeco.llvm.clang.CXCursorVisitor() {
                                        @Override
                                        public int call(
                                                CXCursor base,
                                                CXCursor baseParent,
                                                org.bytedeco.llvm.clang.CXClientData data) {
                                            CXCursor ref =
                                                    org.bytedeco.llvm.global.clang
                                                            .clang_getCursorReferenced(base);
                                            CXCursor target = variableSymbol.getSymbol();
                                            if (target != null
                                                    && org.bytedeco.llvm.global.clang
                                                                    .clang_equalCursors(ref, target)
                                                            != 0) {
                                                result[0] = true;
                                                return org.bytedeco.llvm.global.clang
                                                        .CXChildVisit_Break;
                                            }
                                            return org.bytedeco.llvm.global.clang
                                                    .CXChildVisit_Continue;
                                        }
                                    },
                                    null);
                            return org.bytedeco.llvm.global.clang.CXChildVisit_Break;
                        }
                        return org.bytedeco.llvm.global.clang.CXChildVisit_Continue;
                    }
                },
                null);
        return result[0];
    }

    @Override
    public boolean isInitForVariable(
            CXCursor newClass, @Nonnull TraceSymbol<CXCursor> variableSymbol) {
        return false; // Placeholder
    }
}
