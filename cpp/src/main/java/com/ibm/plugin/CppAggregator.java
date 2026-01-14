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
package com.ibm.plugin;

import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.cpp.CppLanguageSupport;
import com.ibm.mapper.model.INode;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.bytedeco.llvm.clang.CXCursor;

/** Aggregator for C++ language support using Clang/LLVM. */
public final class CppAggregator {

    private static final List<INode> nodes = new ArrayList<>();
    private static final ILanguageSupport<?, CXCursor, ?, ?> languageSupport =
            new CppLanguageSupport();

    private CppAggregator() {
        // Utility class
    }

    @Nonnull
    public static ILanguageSupport<?, CXCursor, ?, ?> getLanguageSupport() {
        return languageSupport;
    }

    public static void addNodes(@Nonnull List<INode> newNodes) {
        nodes.addAll(newNodes);
    }

    @Nonnull
    public static List<INode> getNodes() {
        return new ArrayList<>(nodes);
    }

    public static void clearNodes() {
        nodes.clear();
    }
}
