# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

- **Build all**: `./gradlew build`
- **Build specific module**: `./gradlew :CypherRewritingCore:build`
- **Run tests**: `./gradlew test`
- **Run single test class**: `./gradlew :CypherRewritingCore:test --tests "at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingVisitorTest"`
- **Generate ANTLR sources**: `./gradlew :CypherRewritingCore:generateGrammarSource` (runs automatically before Kotlin compilation)

### Running Verificator Applications

These are Spring Boot apps activated via profiles:

- **Parser/Unparser fuzzing (no database)**: `./gradlew :CypherVerificatorParserUnparser:bootRun --args='--spring.profiles.active=random-no-database'`
- **Parser/Unparser fuzzing (with database)**: `./gradlew :CypherVerificatorParserUnparser:bootRun --args='--spring.profiles.active=random-with-database'`
- **Airbnb data import**: `./gradlew :CypherVerificatorAirbnb:bootRun --args='--spring.profiles.active=airbnb-import'`
- **Airbnb permission fuzzing**: `./gradlew :CypherVerificatorAirbnb:bootRun --args='--spring.profiles.active=airbnb-fuzzer'`

Database-dependent profiles require a Neo4j instance at `bolt://localhost:7687` (user: `neo4j`, password: `adminadmin`).

## Architecture

This is a multi-module Gradle project (Kotlin, Java 21, Spring Boot 4) that **verifies a Cypher query rewriting system for row-level security** in Neo4j. The core idea: intercept Cypher queries, detect patterns matching permission policies, and inject authorization filters (WHERE clauses) to enforce access control.

### Module Dependency Graph

```
CypherRewritingCore (submodule - parser/unparser/enforcer)
├── CypherFuzzer (submodule - query generator using Neo4j Cypher DSL)
│   └── CypherVerificatorParserUnparser (verifies parse→unparse round-trip)
├── CypherFuzzer2 (query generator using direct AST construction)
│   └── CypherVerificatorAirbnb (verifies permission rewriting on real data)
```

### CypherRewritingCore (submodule: `jku-lit-scsl/CypherRewritingCore`)

Core library providing the rewriting pipeline:
1. **Parser** (`CypherRewritingParserImpl`): Cypher string → AST using ANTLR grammar (`Cypher.g4`)
2. **Unparser** (`CypherRewritingUnparserImpl`): AST → Cypher string
3. **Detector** (`PermissionDetectorImpl`): Finds AST patterns matching `PermissionPolicy` rules
4. **Enforcer** (`CypherEnforcerImpl`): Injects WHERE clauses into AST based on detections

AST uses sealed classes: `AstInternalNode`, `AstLeafValue`, `AstLeafNoValue` with types defined in `AstType` enum.

### CypherFuzzer (submodule: `dahoat/CypherFuzzer`)

Generates random valid Cypher queries using Neo4j Cypher DSL. Has three modes: `RandomCypherFuzzer` (random schema), `ExplorerCypherFuzzer` (from existing DB), `TargetCypherFuzzer` (predefined schema).

### CypherFuzzer2

Reimplementation that generates queries by building AST nodes directly (not via Cypher DSL), then rendering via `CypherRewritingUnparser`. Uses `FuzzSettings` builder for configuring generation parameters (pattern length, WHERE complexity, defect injection probabilities, etc.).

### CypherVerificatorParserUnparser

Verifies parser/unparser correctness: generates queries with CypherFuzzer, parses to AST, unparses back, and compares. `RandomFuzzRunnerWithDatabase` additionally executes queries against Neo4j. Outputs reports to `reports/` directory.

### CypherVerificatorAirbnb

End-to-end verification using real Airbnb CSV data. Imports data into Neo4j (Host→Listing→Amenity, User→Review→Listing graph), defines permission policies, then fuzzes: generate query → parse → detect → enforce → execute both original and rewritten → compare results.

## IdentifyReviewAuthorFuzzer Verification Logic

The `IdentifyReviewAuthorFuzzer` verifies the permission rewriting for `(Review)--(User)` patterns. Each generated query is classified into an `AccessPattern`, then four verification checks run in order. Each check has a guard clause that skips it when not applicable for the given pattern.

### Code Structure Principles
Each verification check is a self-contained method with a doc comment explaining the invariant, a guard clause for when it's not applicable, and a single responsibility. Debug counters are isolated in `updateDebugCounters()` so they don't clutter verification logic. The goal: a reviewer should clearly see **what** is being verified and **why** without having to untangle mixed concerns (counters, classification, cache lookups, DB queries, assertions).

### Access Pattern Classification

Every query is classified once in `classifyAccessPattern()` before verification begins:

- **TRAVERSAL**: User is filtered AND returned, Review is neither filtered nor returned. Review is just a hop in the MATCH pattern — no Review data leaks, so no authorization filter is injected.
- **INDIRECT_USER_FILTERED_REVIEW_RETURNED**: WHERE filters User, RETURN returns Review. Indirect access: Review data could leak through the User filter.
- **INDIRECT_REVIEW_FILTERED_USER_RETURNED**: WHERE filters Review, RETURN returns User. Indirect access: User data could leak through the Review filter.
- **OTHER**: Any remaining combination (e.g., same type filtered and returned, missing variables).

### Cache Architecture
- `hostIdForReviewCache` is pre-populated via a bulk query in `preCacheData()` before fuzzing starts (hook in `FuzzBaseRunner`)
- `getHostIdForReview()` is cache-only (no DB fallback) since the data is static

### Verification Checks (in order)

1. **`checkRewrittenResultIsSubsetOfOriginal`** (always runs): Result columns (keys) must be unchanged by rewriting. Rewriting must only remove nodes, never add new ones. Skips key check for `RETURN *` queries.
2. **`checkNoResultsForNonExistentHost`** (skipped for TRAVERSAL): A query rewritten for NON_EXISTENT_HOST="0" must produce no User or Review results, since no data is authorized for a non-existent host. For INDIRECT_USER_FILTERED_REVIEW_RETURNED, also checks that no Review nodes appear. Skipped for TRAVERSAL because the permission system doesn't inject a filter (the rewritten query equals the original).
3. **`checkPerHostCorrectness`** (only when detections exist, requires DB): For each distinct host referenced by original result reviews, rewrites the query for that host and verifies: no authorized results missing (completeness), no new results added (soundness). Checks User nodes always; additionally checks Review nodes for INDIRECT_USER_FILTERED_REVIEW_RETURNED pattern.
4. **`checkMutatedQueryLeaks`** (only for indirect patterns with detections): Compares rewritten results of original vs mutated query (flipped WHERE operator) for NON_EXISTENT_HOST. First verifies the mutated query also returns empty for the non-existent host, then checks that both queries produce identical results. Differences indicate indirect access leaks.

### FuzzSettings for IdentifyReviewAuthorFuzzer
`generateLimit`, `generateSkip`, `asteriskProbability` are disabled to avoid false positives from result-set-altering clauses. `LIMIT`/`SKIP` change which rows appear after filtering, making set comparisons invalid. `RETURN *` returns all variables which complicates label-specific checks.

### Permission Config
`IdentifyReviewAuthorPermissionConfig` resource variable must be `"r"` (Review), not `"u"` (User), because the filter template `(%s:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(:Host {id: %s})` expects a Review node.

## Git Submodules

`CypherFuzzer` and `CypherRewritingCore` are Git submodules. After cloning, run:
```
git submodule update --init --recursive
```