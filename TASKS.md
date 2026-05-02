# TASKS — signet
Progress: 28/51 completed (55%)

## Phase: Setup

- [ ] T001 Initialize project directory structure
- [ ] T002 Verify environment and dependencies

## Phase: Foundational

- [ ] T003 [P] Define shared type: AuditEventKind
- [ ] T004 [P] Define shared type: JsonRpcRequest
- [ ] T005 [P] Define shared type: JsonRpcResponse
- [ ] T006 [P] Define shared type: PedersenCommitment
- [ ] T007 [P] Define shared type: Predicate
- [ ] T008 [P] Define shared type: Tier
- [ ] T009 [P] Define shared type: Timestamp

## Phase: Component

- [x] T010 [P] [signet_vault] Review contract for Signet Vault (contracts/signet_vault/interface.json)
- [x] T011 [signet_vault] Set up test harness for Signet Vault
- [x] T012 [signet_vault] Write contract tests for Signet Vault
- [x] T013 [signet_vault] Implement Signet Vault (implementations/signet_vault/src/)
- [ ] T014 [signet_vault] Run tests and verify Signet Vault
- [x] T015 [signet_cred] Review contract for Signet Credential Engine (contracts/signet_cred/interface.json)
- [x] T016 [signet_cred] Set up test harness for Signet Credential Engine
- [x] T017 [signet_cred] Write contract tests for Signet Credential Engine
- [x] T018 [signet_cred] Implement Signet Credential Engine (implementations/signet_cred/src/)
- [ ] T019 [signet_cred] Run tests and verify Signet Credential Engine
- [x] T020 [signet_proof] Review contract for Signet Proof Workshop (contracts/signet_proof/interface.json)
- [x] T021 [signet_proof] Set up test harness for Signet Proof Workshop
- [x] T022 [signet_proof] Write contract tests for Signet Proof Workshop
- [x] T023 [signet_proof] Implement Signet Proof Workshop (implementations/signet_proof/src/)
- [ ] T024 [signet_proof] Run tests and verify Signet Proof Workshop
- [x] T025 [signet_policy] Review contract for Signet Policy Engine (contracts/signet_policy/interface.json)
- [x] T026 [signet_policy] Set up test harness for Signet Policy Engine
- [x] T027 [signet_policy] Write contract tests for Signet Policy Engine
- [x] T028 [signet_policy] Implement Signet Policy Engine (implementations/signet_policy/src/)
- [ ] T029 [signet_policy] Run tests and verify Signet Policy Engine
- [x] T030 [signet_notify] Review contract for Signet Notification Channel (contracts/signet_notify/interface.json)
- [x] T031 [signet_notify] Set up test harness for Signet Notification Channel
- [x] T032 [signet_notify] Write contract tests for Signet Notification Channel
- [x] T033 [signet_notify] Implement Signet Notification Channel (implementations/signet_notify/src/)
- [ ] T034 [signet_notify] Run tests and verify Signet Notification Channel
- [x] T035 [signet_mcp] Review contract for Signet MCP Server (contracts/signet_mcp/interface.json)
- [x] T036 [signet_mcp] Set up test harness for Signet MCP Server
- [x] T037 [signet_mcp] Write contract tests for Signet MCP Server
- [x] T038 [signet_mcp] Implement Signet MCP Server (implementations/signet_mcp/src/)
- [ ] T039 [signet_mcp] Run tests and verify Signet MCP Server
- [x] T040 [signet_sdk] Review contract for Signet Developer SDK (contracts/signet_sdk/interface.json)
- [x] T041 [signet_sdk] Set up test harness for Signet Developer SDK
- [x] T042 [signet_sdk] Write contract tests for Signet Developer SDK
- [x] T043 [signet_sdk] Implement Signet Developer SDK (implementations/signet_sdk/src/)
- [ ] T044 [signet_sdk] Run tests and verify Signet Developer SDK

---
CHECKPOINT: All leaf components verified

## Phase: Integration

- [ ] T045 [root] Review integration contract for Root
- [ ] T046 [P] [root] Write integration tests for Root
- [ ] T047 [root] Wire children for Root
- [ ] T048 [root] Run integration tests for Root

---
CHECKPOINT: All integrations verified

## Phase: Polish

- [ ] T049 Run full contract validation gate
- [ ] T050 Cross-artifact analysis
- [ ] T051 Update design document
