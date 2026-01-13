# Understanding `LANGUAGE_SUPPORT.md`: A Simplified Guide

This document breaks down the process of adding a new language (C++) and a new cryptography library (OpenSSL) to the Sonar Cryptography Plugin. It simplifies the technical details found in the official `LANGUAGE_SUPPORT.md` documentation.

## Part 1: Adding a New Language (The "Bridge")

Before we can detect OpenSSL usage, the plugin needs to understand C++ code. This is the "Language Support" phase.

### 1. The Dependencies (The "Parser")
We don't write a C++ parser from scratch. We use an existing one (like `sonar-cxx`).
- **Action**: We add the `sonar-cxx` parser as a dependency in our project configuration (`pom.xml`).
- **Goal**: This gives us a tool that can read a `.cpp` file and turn it into a tree structure (AST) that our code can walk through.

### 2. The Four Pillars (The "Generics")
The plugin's engine is generic. To make it work with C++, we must identify 4 specific classes from the `sonar-cxx` parser API that map to the engine's concepts:
1.  **Rule (`R`)**: The class that represents a check or rule in the parser.
2.  **Tree (`T`)**: The class representing a node in the syntax tree (AST).
3.  **Symbol (`S`)**: The class representing semantic info (types, variables).
4.  **Publisher (`P`)**: The class that handles context for a specific file being scanned.

### 3. The Engine Implementation (The "Adapter")
We must write "Adapter" code to translate between `sonar-cxx` and our Engine. This involves implementing 5 key interfaces:
-   **`ILanguageSupport`**: The main connector. It groups everything else together.
-   **`IBaseMethodVisitor`**: A tool that visits every method/function in the C++ code.
-   **`IDetectionEngine`**: The logic that runs our rules on the C++ tree.
-   **`ILanguageTranslation`**: A helper that converts C++ AST nodes into simple Strings (e.g., getting the name of a function).
-   **`IScanContext`**: Holds info about the current file (e.g., filename, line numbers).

### 4. The Plugin Registration (The "Hook")
Finally, we "hook" this new C++ support into the main SonarQube plugin.
-   **File Extensions**: We tell the plugin to scan `.cpp`, `.c`, `.h` files.
-   **Registrars**: We write a class (e.g., `CppCheckRegistrar`) that tells SonarQube "Hey, I have some rules for C++ code!".

---

## Part 2: Adding a Library (The "OpenSSL Integration")

Once the plugin speaks C++, we teach it to spot OpenSSL specific code.

### 1. Verification First (TDD)
We don't guess. We verify.
-   **Test File**: We create a real C++ file (`test/files/rules/detection/openssl/AesTestFile.cpp`) that uses OpenSSL functions (e.g., `EVP_EncryptInit`).
-   **Unit Test**: We write a Java test that runs our (future) rule against this file and fails if it doesn't find anything.

### 2. The Rule Structure
We organize rules by library.
-   **Directory**: `cpp/src/main/java/com/ibm/plugin/rules/detection/openssl/`
-   **The Rule File**: A Java file (e.g., `OpenSslEvpContext.java`) that defines the rule.

### 3. Writing the Rule (The "Builder")
We use a fluent API to describe the OpenSSL function we want to catch.
*Example for capturing `EVP_EncryptInit`*:
```java
new DetectionRuleBuilder<Tree>()
    .createDetectionRule()
    .forMethods("EVP_EncryptInit") // The function name
    .shouldBeDetectedAs(new ValueActionFactory<>("EVP_CIPHER_CTX")) // What concept is this?
    .withMethodParameter("EVP_CIPHER_CTX *") // Argument 1
    .withMethodParameter("EVP_CIPHER *")     // Argument 2
        .shouldBeDetectedAs(new AlgorithmFactory<>()) // Capture the algorithm here!
    .buildForContext(new CipherContext())
    .inBundle(() -> "OpenSsl") // Mark as OpenSSL
```

### 4. Translation & Mapping
Finding the string "EVP_aes_256_cbc" is not enough. We need to tell the system this means "AES Algorithm" with "256 bit key" and "CBC Mode".
-   **Mapper**: We write a mapper class that translates "EVP_aes_256_cbc" -> `new Aes(256, CBC)`.
-   **Model**: We map it to the standardized Cryptography Model used by the plugin.

### 5. Final Output
The engine combines all these Translated Nodes into a final tree, which is then written out as the CBOM (Cryptography Bill of Materials).

---

## Task: Support OpenSSL 3.6.0
For your specific request to support OpenSSL 3.6.0 (assuming you mean the latest 3.x series, as 3.4 is the current latest stable, we will target the 3.x API which is largely compatible):
1.  **Focus**: We will target the `EVP` (Envelope) API, as it is the high-level standard for OpenSSL 3.0+.
2.  **Key Functions to Map**:
    -   `EVP_EncryptInit_ex`, `EVP_DecryptInit_ex` (Context initialization)
    -   `EVP_PKEY_...` (Public Key ops)
    -   `OSSL_PROVIDER_...` (Provider loading, specific to 3.0)

This structure allows us to support C++ generally, and then specifically plug in knowledge about OpenSSL without mixing the two concerns.
