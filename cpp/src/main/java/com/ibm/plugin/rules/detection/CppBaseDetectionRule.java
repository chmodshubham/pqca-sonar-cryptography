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
package com.ibm.plugin.rules.detection;

/**
 * Placeholder class for C++ detection rules.
 *
 * <p>The actual C++ language support has been migrated to use Clang/LLVM and is now implemented in
 * the engine module under com.ibm.engine.language.cpp
 *
 * <p>This class is kept as a stub to maintain module structure during migration.
 */
public abstract class CppBaseDetectionRule {
    // Migration note: This class previously extended sonar-cxx SquidCheck
    // The new implementation uses Clang/LLVM AST parsing via JavaCPP
    // See: engine/src/main/java/com/ibm/engine/language/cpp/
}
