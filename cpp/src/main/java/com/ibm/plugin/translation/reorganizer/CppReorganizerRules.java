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
package com.ibm.plugin.translation.reorganizer;

import com.ibm.mapper.reorganizer.IReorganizerRule;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

/** Reorganizer rules for C++ cryptographic findings. */
public final class CppReorganizerRules {

    private CppReorganizerRules() {
        // Utility class
    }

    @Nonnull
    public static List<IReorganizerRule> rules() {
        // TODO: Implement reorganizer rules
        return Collections.emptyList();
    }
}
