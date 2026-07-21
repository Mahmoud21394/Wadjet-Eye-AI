# AiSOC Technical Assessment Report
## Wadjet-Eye AI Platform — Integration & Replacement Analysis

**Report Date:** 2026-07-21
**Repository:** `https://github.com/beenuar/AiSOC` (commit HEAD, VERSION `7.6.0`)
**Analyst:** AI Developer Agent (Genspark)
**Scope:** Full architectural analysis of AiSOC v7.6.0 to determine replacement, integration, and
ignore decisions for every functional module of the Wadjet-Eye AI platform.
**Classification:** Internal — Engineering

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Repository Deep Analysis](#2-repository-deep-analysis)
3. [Architecture Analysis](#3-architecture-analysis)
4. [Functional Mapping Table](#4-functional-mapping-table)
5. [Module Replacement Matrix](#5-module-replacement-matrix)
6. [Gap Analysis](#6-gap-analysis)
7. [Integration Architecture Diagram](#7-integration-architecture-diagram)
8. [API Integration Plan](#8-api-integration-plan)
9. [AI Architecture Assessment](#9-ai-architecture-assessment)
10. [Infrastructure Assessment](#10-infrastructure-assessment)
11. [Migration Roadmap (5 Phases)](#11-migration-roadmap-5-phases)
12. [Risk Assessment](#12-risk-assessment)
13. [Final Recommendation](#13-final-recommendation)
14. [Action Plan](#14-action-plan)

---

## 1. Executive Summary

AiSOC v7.6.0 is a mature, MIT-licensed open-source AI Security Operations Center implemented as
a **polyglot microservices monorepo** with 19 application services, 13 supporting infrastructure
containers, 78 integration plugins, a 417-item curated detection marketplace, and a comprehensive
multi-tenant RBAC system. It has completed a documented 13-phase hardening programme and a
5-phase "Fully-Operational AI-SOC" build-out, reaching a stated claim-to-gate ratio of
**33 GATED / 7 PARTIAL / 0 NO GATE**.

**Core finding:** AiSOC is not a drop-in replacement for the Wadjet-Eye platform. The two
systems differ fundamentally in deployment model (Wadjet-Eye is a single-page frontend over a
Supabase backend; AiSOC is a microservices backend platform). However, AiSOC provides
**superior, production-grade implementations** of five capability domains that Wadjet-Eye
currently implements from scratch or stub:

| Capability | Wadjet-Eye Current | AiSOC Equivalent | Recommendation |
|---|---|---|---|
| AI Investigation | Custom GPT prompt chain | Dual LangGraph (`workflow.py` + `orchestrator.py`) with swarm, OTel, ledger | **Integrate via API** |
| UEBA / Anomaly Detection | Placeholder/partial | Welford baseline + RSS composite scorer + peer-group deviation | **Integrate via API** |
| Threat Intelligence | Manual IOC enrichment | MISP/OTX/CISA-KEV/TAXII + Bloom dedup + OpenSearch/Qdrant/Neo4j | **Integrate via API** |
| Alert Fusion / Correlation | Single-service alert store | FusionEngine: Deduplicator + Correlator + EntityRisk + ConfidenceScorer | **Integrate via API** |
| Compliance Evidence | UI only | SHA-256 tamper-evident hash chain, 5 frameworks, DORA/HIPAA/ISO/PCI | **Integrate via API** |
| RBAC / Multi-tenancy | Custom JS + Supabase RLS | PostgreSQL RLS + `SET LOCAL app.current_tenant_id` + MSSP hierarchy | **Adopt schema** |
| SSO / Auth | JWT + custom | OIDC PKCE + SAML 2.0 SP + PKCE + JWT issuance with default-secret guard | **Adopt patterns** |

**Strategic verdict:** The recommended path is **selective API integration**, not wholesale
replacement. Deploy AiSOC's backend as an auxiliary microservices layer alongside Wadjet-Eye's
existing frontend, consuming AiSOC's REST and WebSocket APIs for investigation, UEBA, threat
intel, fusion, and compliance. Retain Wadjet-Eye's frontend, branding, navigation, and
Supabase data layer for modules AiSOC does not improve (Global Threat Map, CDWIE, WS1–WS10
widgets, IOC lookup UI).

**Estimated integration timeline:** 16–20 weeks across 5 phases.
**Licence risk:** None. AiSOC is MIT-licensed (`LICENSE` file confirmed).
**Operational overhead:** Significant. Full AiSOC stack requires 27 Docker containers,
ClickHouse, OpenSearch, Qdrant, Neo4j, Kafka, and Redis. A lite integration path using only
the `api` + `agents` + `fusion` services cuts this to ~8 containers.

---

## 2. Repository Deep Analysis

### 2.1 Repository Vital Statistics

| Metric | Value | Source |
|---|---|---|
| Version | `7.6.0` | `VERSION` |
| Helm chart version | `5.2.0` | `infra/helm/aisoc/Chart.yaml` |
| License | MIT | `LICENSE` |
| Application services | 19 | `services/` directory |
| Infrastructure containers | 27 total (compose) | `docker-compose.yml` |
| API endpoint files | 72 Python files | `services/api/app/api/v1/endpoints/` |
| API endpoint LOC | 29,311 lines | `wc -l endpoints/*.py` |
| Integration plugins | 78 | `plugins/` directory |
| Marketplace items (curated) | 417 | `marketplace/curated.json` |
| Marketplace detection rules | 7,008 | `marketplace/index.json` (sum) |
| Playbooks | 62 | per prior enumeration |
| SDKs | TypeScript, Python, Go | `packages/sdk-ts/`, `sdk-py/`, `sdk-go/` |
| CLI tools | `aisoc-cli`, `aisoc-lite` | `packages/aisoc-cli/`, `aisoc-lite/` |
| Frontend | Next.js (`apps/web/`) | `apps/web/` |
| Documentation | Docusaurus (`apps/docs/`) | `apps/docs/` |
| Hardening phases completed | 13 of 13 (phases 0–12) | `ROADMAP.md` |
| CI claim gates | 33 GATED / 7 PARTIAL | `ROADMAP.md` |

### 2.2 Service Inventory

The 19 application microservices are:

| Service | Language | Primary Role |
|---|---|---|
| `api` | Python / FastAPI | REST API gateway, auth, RBAC, cases, investigations |
| `agents` | Python / FastAPI | LangGraph investigation orchestration, LLM gateway |
| `ingest` | Go (zerolog, pgx) | OCSF normalisation, Kafka producer, Neo4j graph writer |
| `enrichment` | Python | IP/domain/hash enrichment via external threat feeds |
| `fusion` | Python | Alert deduplication, correlation, confidence scoring, ClickHouse lake |
| `threatintel` | Python | MISP/OTX/CISA-KEV/TAXII polling, Bloom filter, OpenSearch/Qdrant/Neo4j |
| `ueba` | Python | Welford baseline, z-score scoring, peer-group anomaly detection |
| `actions` | Python | Automated response actions, dry-run policy, blast-radius |
| `connectors` | Python | 78 source integrations (SIEM, EDR, cloud, identity) |
| `realtime` | TypeScript (Node.js) | WebSocket event bus, graph update streaming |
| `honeytokens` | Python | Decoy credential deployment and alert generation |
| `purple-team` | Python | Attack simulation, detections-vs-simulations coverage |
| `mcp` | TypeScript | Model Context Protocol server + Cursor extension |
| `mesh` | Python | Service mesh telemetry and health aggregation |
| `slack-bot` | Python | Slack alert notification and triage channel integration |
| `teams-bot` | Python | Microsoft Teams integration |
| `osquery-tls` | Python | osquery TLS endpoint server |
| `osquery-extensions` | Python | Custom osquery extension tables |
| `demo-producer` | Python | Synthetic event generator for demos and CI |

### 2.3 Package and Tooling Ecosystem

```
packages/
  sdk-ts/           TypeScript client SDK (auto-generated from openapi.yaml)
  sdk-py/           Python client SDK
  sdk-go/           Go client SDK
  plugin-sdk-go/    Plugin development kit (Go)
  plugin-sdk-py/    Plugin development kit (Python)
  aisoc-cli/        npx aisoc — zero-install front door (triage, translate, up)
  aisoc-lite/       Lightweight deterministic triage engine (no LLM required)
  aisoc-sandbox/    Isolated code-execution sandbox for agent tool calls
  aisoc-action/     GitHub Actions action for CI-integrated alert triage
  ocsf/             OCSF schema types and validation
  report-card/      SVG/Markdown report card generator
  types/            Shared TypeScript types
  ui/               Shared React component library
```

### 2.4 Infrastructure Footprint

**Full stack (docker-compose.yml):**
- **Databases:** PostgreSQL 16 (primary), ClickHouse (event lake), Redis 7 (cache + Bloom filter + UEBA signal bus)
- **Search:** OpenSearch 2 (IOC full-text search, threat intel)
- **Graph:** Neo4j 5 + APOC (entity relationship graph, attack path)
- **Vectors:** Qdrant (MITRE ATT&CK RAG embeddings, threat intel semantic search)
- **Messaging:** Kafka 3 / Confluent 7.5 + Zookeeper (event backbone)
- **LLM Gateway:** LiteLLM (OpenAI-compatible proxy with task-alias routing)
- **Monitoring:** Prometheus + Alertmanager + Grafana
- **Deployment targets:** Helm/K8s, Terraform (AWS + Azure + BYOC), Fly.io, Render, Coolify, Cloudflare, Railway

**Lite integration path (minimum viable):**
- PostgreSQL + Redis + `api` + `agents` + `fusion` = 5 containers
- Removes: Kafka, ClickHouse, OpenSearch, Qdrant, Neo4j, osquery, honeytokens, purple-team

### 2.5 Detection Content Quality

The AiSOC marketplace ships:
- **417 curated detections** across cloud (164), endpoint (117), identity (70), application (33), data-exfil (20), network (12)
- Detection pipeline gates: Phase 4a DAC (de-circularised) + Phase 4b executable truth table (825 rules confirmed executable vs imported)
- `DetectionEngine` in `fusion/app/services/detection_engine.py` evaluates rules live on the Kafka event stream

---

## 3. Architecture Analysis

### 3.1 Wadjet-Eye Architecture (Current)

Wadjet-Eye is a **monolithic single-page application** with:
- A vanilla JavaScript frontend (`index.html` + `js/*.js` modules)
- Supabase (PostgreSQL + Auth + Realtime) as the backend
- No dedicated microservices — all business logic in browser-executed JS
- Custom RBAC module (`js/rbac.js`) with Supabase RLS as the enforcement layer
- Module-per-concern JS files (~25 JS modules: `nexus.js`, `global-threat-landscape.js`,
  `cyber-defense.js`, `identity-intelligence.js`, `threat-hunting.js`, etc.)

**Strengths:**
- Zero infrastructure overhead (Supabase is hosted)
- Instant deployment (static files + Supabase project)
- Custom UI/UX control

**Weaknesses:**
- AI logic lives in browser JS — no persistent agent state, no streaming investigation
- No event ingestion pipeline (no OCSF normalisation, no Kafka)
- UEBA, threat intel, and alert fusion are partially stubbed or use client-side simulation
- Compliance evidence is UI-only with no tamper-evident storage
- Auth limited to Supabase JWT; no OIDC/SAML for enterprise SSO

### 3.2 AiSOC Architecture

AiSOC is a **cloud-native microservices platform** following an event-driven architecture:

```
Connectors (78) → Ingest (Go) → Kafka → Fusion → PostgreSQL/ClickHouse
                                    ↓
                              Enrichment / UEBA / ThreatIntel
                                    ↓
                              Agents (LangGraph) → Investigation Ledger
                                    ↓
                              Actions (Automated Response)
                                    ↓
                              Realtime (WebSocket) → Next.js UI
```

**Event flow:**
1. **Connectors** poll or receive webhooks from 78 source integrations
2. **Ingest** (Go) normalises raw events to OCSF format, writes to Kafka `raw-events` topic
   and simultaneously upserts entity nodes/edges into Neo4j via batched UNWIND queries
3. **Fusion** consumes Kafka, deduplicates (Redis), correlates, scores entity risk,
   optionally appends UEBA signals, and writes fused alerts to PostgreSQL + ClickHouse
4. **Agents** receive alert triggers via REST, execute dual LangGraph pipelines:
   - Primary: `auto_triage → triage → enrichment → investigation → attack_path`
   - Investigator: `recon → forensic → responder → report_writer`
5. **Actions** execute containment with dry-run policy, blast-radius checks, and
   human approval via SLA-timer durable approval system
6. **Realtime** (Node.js) consumes `security.graph_updates` Kafka topic and pushes
   live UI updates via WebSocket

### 3.3 Fundamental Architectural Difference

| Dimension | Wadjet-Eye | AiSOC |
|---|---|---|
| Deployment model | SPA + Supabase (2 tiers) | Microservices (19 services + 13 infra) |
| AI execution | Browser JS / Supabase Edge | Python FastAPI async + LangGraph |
| Event pipeline | None | Kafka + OCSF normalisation |
| Data stores | Supabase PostgreSQL only | PG + Redis + ClickHouse + OpenSearch + Qdrant + Neo4j |
| Auth | Supabase JWT | OIDC PKCE + SAML 2.0 + JWT |
| Tenancy model | Supabase RLS | PostgreSQL RLS + `SET LOCAL` + MSSP hierarchy |
| Graph analytics | None | Neo4j APOC + attack path analysis |
| LLM routing | Direct OpenAI calls | LiteLLM task-alias gateway |

**Implication:** Direct replacement is not architecturally feasible without rewriting
the entire Wadjet-Eye frontend. The correct path is **API integration** — Wadjet-Eye's
frontend consumes AiSOC's REST APIs for the capabilities where AiSOC is superior.

### 3.4 Tenancy Architecture

AiSOC implements **three-layer tenant isolation**:

1. **PostgreSQL RLS** (`services/api/app/db/rls.py`):
   ```python
   await session.execute(
       text("SELECT set_config('app.current_tenant_id', :tid, TRUE)"),
       {"tid": str(tenant_id)},
   )
   ```
   Every transaction sets `app.current_tenant_id` as a session-local variable, activating
   RLS policies defined in `migrations/002_rls.sql`.

2. **MSSP hierarchy** (`services/api/app/models/tenant.py`):
   ```python
   parent_tenant_id: Mapped[uuid.UUID | None]
   mssp_role: Mapped[str | None]
   ```
   Supports multi-level managed security provider trees where parent tenants can
   administer child tenants.

3. **Application-layer double-filter**: All endpoints additionally apply explicit
   `WHERE tenant_id = user.tenant_id` as defence-in-depth against misconfigured RLS.

This is materially stronger than Wadjet-Eye's current single-layer Supabase RLS.

---

## 4. Functional Mapping Table

The table below maps every major functional module in Wadjet-Eye to its AiSOC equivalent,
with replacement/integration/ignore verdicts.

| Wadjet-Eye Module | JS File | AiSOC Equivalent | Service | Replace? | Integrate? | Keep Existing? | Reason |
|---|---|---|---|---|---|---|---|
| **AI Investigation Copilot** | `nexus.js`, `ai-assistant.js` | Dual LangGraph + swarm | `agents/` | No | **Yes** | Partial | AiSOC has OTel spans, cost tracking, streaming, immutable ledger. Keep WE UI, replace backend. |
| **Alert Management** | `alerts.js` | `/api/v1/alerts` endpoint | `api/` | No | **Yes** | No | AiSOC's `AlertSink` + ClickHouse lake + fusion scoring far exceeds WE stub. Migrate alert store. |
| **Case Management** | `cases.js` | `/api/v1/cases` 1,388-line endpoint | `api/` | No | **Yes** | No | AiSOC has forward-only state machine, observable graph, MITRE coverage, SSRF-guarded agents proxy. |
| **RBAC Administration** | `rbac.js` | `/api/v1/rbac` + RBAC ORM | `api/` | No | **Adopt schema** | Partial | AiSOC's PG RLS + tenant-scoped roles is stronger. Keep WE UI, replace backend schema/API. |
| **Multi-Tenancy** | `rbac.js` + Supabase | `models/tenant.py` + `db/rls.py` | `api/` | No | **Adopt pattern** | Partial | MSSP hierarchy + `SET LOCAL` RLS pattern is superior. Adopt in WE's Supabase layer. |
| **UEBA / Behavioural Analytics** | `identity-intel.js` (partial) | `ueba/` service | `ueba/` | No | **Yes** | No | Welford baseline + RSS composite + peer-group deviation is production-grade; WE has stubs. |
| **Threat Intelligence** | `threat-intel.js` | `threatintel/` service | `threatintel/` | No | **Yes** | No | MISP/OTX/CISA-KEV/TAXII + Bloom dedup + Qdrant RAG replaces manual IOC enrichment. |
| **Alert Fusion / Correlation** | None (stub) | `fusion/` FusionEngine | `fusion/` | N/A | **Yes** | N/A | WE has no fusion engine. AiSOC's Deduplicator+Correlator+EntityRisk+ConfidenceScorer fills a gap. |
| **Global Threat Map** | `global-threat-landscape.js` | No equivalent | — | No | No | **Yes** | AiSOC has no world atlas threat map. WE's D3.js/TopoJSON implementation (PR #192) is unique. |
| **SOC Campaigns / Detections** | `campaigns-detections.js` | `detections/` + marketplace (417 rules) | `fusion/DetectionEngine` | No | **Yes** | Partial | WE UI is custom; AiSOC's 417 curated + live DetectionEngine on Kafka stream is superior content. |
| **Compliance Reporting** | `compliance.js` (UI only) | `endpoints/compliance.py` + 5 YAML frameworks | `api/` | No | **Yes** | Partial | SHA-256 tamper-evident hash chain + SOC2/PCI-DSS/HIPAA/ISO27001/NIST-CSF in code is far stronger. |
| **Authentication / SSO** | Supabase Auth | OIDC PKCE + SAML 2.0 SP + JWT | `api/auth/oidc.py` + `saml.py` | No | **Adopt** | Partial | AiSOC implements PKCE, blocks default JWT secrets, supports enterprise IdPs. |
| **Playbook / SOAR** | `soar.js` (partial) | `playbooks/` + 62 playbooks + actions service | `actions/` | No | **Yes** | No | AiSOC has DAG engine, dry-run, blast-radius, approval SLA timers, 62 shipped playbooks. |
| **Threat Hunting** | `threat-hunting.js` | `/api/v1/hunts`, `saved_hunts`, NL query | `api/` | No | **Yes** | Partial | AiSOC has NL→KQL/SPL/ES|QL translation, saved hunts, ClickHouse data explorer. |
| **Graph / Network Analysis** | `threat-graph.js` | `graph.py`, `identity_graph.py`, Neo4j | `ingest/` + `api/` | No | **Yes** | Partial | AiSOC's Neo4j attack-path analysis and entity graph replaces WE's D3 static graph. |
| **Metrics / Dashboard** | `dashboard.js` | `/api/v1/metrics` (1,000-line endpoint) | `api/` | No | **Yes** | Partial | Keep WE UI widgets; source data from AiSOC metrics API. |
| **Connector Management** | `connectors.js` | `/api/v1/connectors` + 78 plugins | `api/` + `connectors/` | No | **Yes** | No | AiSOC has 78 live integrations with runtime conformance gate vs WE's manual connector stubs. |
| **Identity Intelligence** | `identity-intel.js` | `identity_graph.py`, `identity_timeline.py` | `api/` | No | **Yes** | Partial | AiSOC provides identity graph + timeline API; WE frontend can consume. |
| **Insider Threat** | `insider-threat.js` | `insider_threat.py` endpoint + InsiderThreatAgent | `api/` + `agents/` | No | **Yes** | No | AiSOC has dedicated agent (`insider_threat_agent.py`) + endpoint; WE has UI stub. |
| **Attack Chain Analysis** | None | `attack_chain.py` + `AttackChainGrouper` | `api/` + `fusion/` | N/A | **Yes** | N/A | WE has no attack chain service. AiSOC fills gap with fuse-time chain grouping + Neo4j. |
| **Posture / EASM** | `posture.js` | `posture.py` + `easm.py` + C2/C3 phases | `api/` | No | **Yes** | Partial | AiSOC's effective-permissions loader + autopilot posture scorecard is richer. |
| **Realtime / WebSocket** | `realtime.js` (partial) | `realtime/` Node.js service | `realtime/` | No | **Yes** | Partial | AiSOC's graph-update streaming via `security.graph_updates` Kafka topic is production-grade. |
| **Honeytokens** | None | `honeytokens/` service | `honeytokens/` | N/A | **Yes** | N/A | WE has no honeytoken capability. Pure net-new from AiSOC. |
| **Purple Team / Simulation** | None | `purple-team/` service | `purple-team/` | N/A | **Yes** | N/A | WE has no attack simulation. AiSOC's purple team detection coverage testing fills gap. |

---

## 5. Module Replacement Matrix

### 5.1 Replace Decisions (Backend Only — UI Retained)

The following AiSOC backend components should **replace** the equivalent Wadjet-Eye backend
implementations. In all cases the Wadjet-Eye frontend UI is retained and updated to call
the AiSOC REST API instead of Supabase directly.

#### 5.1.1 Alert Fusion Engine
- **Replace:** Wadjet-Eye's direct Supabase `alerts` table inserts
- **With:** AiSOC `fusion/` service — `FusionEngine` class (`fusion/app/services/fusion_engine.py`)
- **Why:** Deduplication (Redis Bloom filter), correlation (temporal window), entity risk scoring,
  UEBA signal fusion, attack-chain grouping, ClickHouse event lake — none of these exist in WE
- **Integration point:** `POST /api/v1/alerts` → AiSOC `api` service; or direct Kafka produce
- **Files:** `services/fusion/app/main.py`, `services/fusion/app/services/fusion_engine.py`

#### 5.1.2 AI Investigation Pipeline
- **Replace:** Wadjet-Eye's browser-side GPT prompt chain in `nexus.js`
- **With:** AiSOC `agents/` service — `InvestigatorOrchestrator` + `build_investigation_graph()`
- **Why:** AiSOC provides streaming WebSocket delivery, immutable append-only `InvestigationEvent`
  ledger, OpenTelemetry spans per agent node, per-run cost tracking (`CostTracker`), and fail-closed
  `LLMInputContract` that blocks raw log/OCSF data from reaching LLMs
- **Files:** `services/agents/app/investigator/orchestrator.py`,
  `services/agents/app/graph/workflow.py`, `services/agents/app/llm/contract.py`

#### 5.1.3 UEBA Scoring
- **Replace:** Any client-side behavioural analytics in WE
- **With:** AiSOC `ueba/` service — `ScoringService` + `BaselineService`
- **Why:** Welford online statistics (incremental mean/variance without full window replay),
  per-entity baseline, peer-group deviation blending, RSS composite z-score — none of this
  exists in WE
- **Files:** `services/ueba/app/services/scoring.py`, `services/ueba/app/services/baseline.py`

#### 5.1.4 Threat Intelligence Feed Pipeline
- **Replace:** Manual IOC lookups in WE's `threat-intel.js`
- **With:** AiSOC `threatintel/` service
- **Why:** Continuous polling of MISP, OTX, CISA KEV, TAXII; Redis Bloom filter dedup;
  multi-store write (OpenSearch + Qdrant + Neo4j); `ThreatActorAttributionEngine`;
  air-gap mode with allowlist for internal MISP servers
- **Files:** `services/threatintel/app/main.py`, `services/threatintel/app/actors/attribution.py`

#### 5.1.5 RBAC Backend Schema
- **Replace:** WE's custom `js/rbac.js` backend interaction (Supabase tables)
- **With:** AiSOC RBAC schema: `Permission → Role → RolePermission → UserRole` with
  `UniqueConstraint("tenant_id", "name")` and cascade deletes
- **Why:** AiSOC's schema is more correct — platform-wide Permission catalogue seeded
  via migration, tenant-scoped roles, proper many-to-many with cascade deletes
- **Files:** `services/api/app/models/rbac.py`, `services/api/app/api/v1/endpoints/rbac.py`

#### 5.1.6 Case Management Backend
- **Replace:** Wadjet-Eye's Supabase case records (if any)
- **With:** AiSOC `/api/v1/cases` with forward-only state machine, observable graph,
  evidence chain, MITRE coverage map, ITSM fan-out, SSRF-guarded agent proxy
- **Why:** AiSOC enforces `new → triaged → investigating → contained → resolved → closed`
  transitions at the API layer; WE has no equivalent enforcement
- **Files:** `services/api/app/api/v1/endpoints/cases.py` (1,388 LOC)

### 5.2 Integrate Decisions (Consume AiSOC API from WE Frontend)

The following AiSOC capabilities should be consumed as API services without replacing
WE's frontend:

| Module | AiSOC Endpoint | Call Pattern |
|---|---|---|
| Compliance evidence | `GET/POST /api/v1/compliance/*` | WE compliance UI → AiSOC REST |
| Playbook execution | `POST /api/v1/playbooks/{id}/run` | WE SOAR panel → AiSOC REST |
| NL threat hunting | `POST /api/v1/nl_query` | WE hunting UI → AiSOC REST |
| Detection rules | `GET /api/v1/detection_rules` | WE campaigns tab → AiSOC REST |
| Identity graph | `GET /api/v1/identity_graph` | WE identity panel → AiSOC REST |
| Graph analysis | `GET /api/v1/graph` | WE threat graph → AiSOC REST |
| EASM / posture | `GET /api/v1/posture`, `/easm` | WE posture tab → AiSOC REST |
| Realtime updates | `wss://aisoc/ws` | WE dashboard → AiSOC WebSocket |
| Insider threat | `GET /api/v1/insider_threat` | WE insider tab → AiSOC REST |
| Attack chain | `GET /api/v1/attack_chain` | WE timeline view → AiSOC REST |

### 5.3 Keep (No AiSOC Equivalent)

| Wadjet-Eye Module | Reason to Keep |
|---|---|
| Global Cyber Threat Map | AiSOC has no D3.js/TopoJSON world atlas threat map. WE's cinematic map (PR #192) is a unique UI differentiator. |
| Custom CDWIE widgets | WE's Cyber Defence Workspace Intelligence Engine widgets (WS1–WS10) are custom interactive visualisations with no AiSOC equivalent. |
| Radar/KPI dashboards | WE's animated KPI cards, sparklines, and SOC aesthetic are custom UI assets. |
| Supabase Auth (interim) | Retain Supabase Auth for initial integration; migrate to AiSOC OIDC when SSO is required. |

---

## 6. Gap Analysis

### 6.1 Capabilities AiSOC Provides That Wadjet-Eye Lacks

These are **net-new capabilities** gained by integrating AiSOC:

#### 6.1.1 Dual LangGraph Investigation Pipeline (Critical Gap)
- **What:** Parallel hypothesis swarm (`asyncio.gather` over 5 competing hypotheses),
  deterministic keyword+technique scoring, two-graph orchestration with early FP exit
- **Why critical:** WE has no persistent investigation state. Browser-side GPT calls
  have no audit trail, no cost tracking, and no fail-closed data validation.
- **Files:** `services/agents/app/swarm/swarm.py`, `services/agents/app/graph/workflow.py`

#### 6.1.2 LLMInputContract (Security Gap)
- **What:** Fail-closed validator that blocks `class_uid`, `activity_id`, `EventID`,
  `_raw`, `sourcetype` and secret-shaped patterns from reaching LLMs. Runtime toggle
  `AISOC_AGENTS_LLM_CONTRACT_ENFORCED`. 60,000-character message cap.
- **Why critical:** WE currently passes raw alert data to OpenAI. This is a data
  exfiltration risk for enterprise customers.
- **File:** `services/agents/app/llm/contract.py`

#### 6.1.3 LiteLLM Multi-Model Gateway (Architectural Gap)
- **What:** 7 task aliases (`aisoc-triage`, `aisoc-investigation`, `aisoc-recon`, etc.)
  routed to different models. Air-gapped Ollama/vLLM swap by config only. No AiSOC code
  change required to swap models.
- **Why critical:** WE is hardcoded to OpenAI. AiSOC enables model-provider agnosticism.
- **File:** `infra/litellm/config.yaml`

#### 6.1.4 Kafka Event Backbone (Scale Gap)
- **What:** Topic-per-service pattern. Ingest writes to `raw-events`; Fusion consumes
  and writes to `alerts`; Realtime consumes `security.graph_updates`.
- **Why critical:** WE has no event-driven pipeline. At scale (thousands of events/sec),
  Supabase real-time subscriptions cannot replace a partitioned Kafka topic.

#### 6.1.5 Neo4j Attack Path Analysis (Capability Gap)
- **What:** Entity graph (users, IPs, hosts, processes) with APOC-powered attack path
  traversal. Ingest writes via batched UNWIND MERGE on `natural_key`.
- **Why critical:** WE's `threat-graph.js` uses static D3 node-link diagrams. AiSOC
  provides live, queryable attack paths derived from real ingested events.

#### 6.1.6 Append-Only Investigation Ledger (Audit Gap)
- **What:** `InvestigationEvent` table with SQL immutability trigger. Stores input hash,
  output hash, duration_ms, and full agent metadata per step.
- **Why critical:** WE has no audit trail for AI decisions. Regulatory compliance
  (SOC 2, ISO 27001) requires demonstrable AI decision lineage.

#### 6.1.7 Honeytoken Deployment (Missing Capability)
- **What:** `services/honeytokens/` — decoy credential generation, deployment, and
  alert generation when honeytoken is used.
- **Why critical:** WE has zero deception technology. AiSOC adds a zero-false-positive
  detection layer.

#### 6.1.8 Purple Team / Detection Coverage (Missing Capability)
- **What:** `services/purple-team/` — attack simulations mapped to detections,
  coverage gap reporting, detection-vs-simulation CI gate.
- **Why critical:** WE cannot validate whether its detections fire on real attack TTPs.

### 6.2 Capabilities Wadjet-Eye Has That AiSOC Lacks

| WE Capability | Gap in AiSOC | Impact |
|---|---|---|
| Cinematic D3.js World Threat Map | AiSOC has no geo-visualisation component | WE retains this; no migration needed |
| Custom SOC UI/UX aesthetic | AiSOC's Next.js frontend has different design language | WE frontend must be retained |
| CDWIE workstation modules (WS1–10) | No equivalent in AiSOC | Keep WE modules |
| Single SPA deployment (no infra) | AiSOC requires 8–27 containers | WE is simpler to deploy |

### 6.3 Schema and Data Model Gaps

If integrating AiSOC alongside WE, the following data model reconciliation is needed:

1. **Alert ID namespace:** WE uses Supabase UUID; AiSOC uses PostgreSQL UUID with tenant scope.
   A cross-reference table or single source-of-truth (pick one) is required.
2. **Tenant representation:** WE uses Supabase auth `user.app_metadata.tenant_id`;
   AiSOC uses `tenants.id` UUID with `slug`. A mapping layer is needed.
3. **Case numbering:** AiSOC uses `INC-001` short IDs per tenant; WE uses UUID slugs.
   The `_resolve_case_id` helper in AiSOC's cases endpoint handles this, but WE must
   adopt the AiSOC format.
4. **OCSF event format:** AiSOC ingests OCSF-normalised events. WE's existing alert
   format (Supabase JSON) must be transformed to OCSF before feeding AiSOC's ingest layer.

---

## 7. Integration Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  WADJET-EYE FRONTEND (Retained — index.html + js/*.js)                       │
│                                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ Global Threat│  │  CDWIE/WS    │  │  Nexus AI    │  │  RBAC Admin +    │ │
│  │ Map (D3+Topo)│  │  Modules     │  │  Copilot     │  │  Tenant Mgmt     │ │
│  │  (KEEP)      │  │  (KEEP)      │  │  (MIGRATE)   │  │  (MIGRATE)       │ │
│  └──────────────┘  └──────────────┘  └──────┬───────┘  └────────┬─────────┘ │
│                                             │                    │           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────┴───────┐  ┌────────┴─────────┐ │
│  │  Campaigns/  │  │  Compliance  │  │  Cases /     │  │  Connectors /    │ │
│  │  Detections  │  │  Evidence    │  │  Alerts      │  │  UEBA / ThreatIn │ │
│  │  (MIGRATE)   │  │  (MIGRATE)   │  │  (MIGRATE)   │  │  (MIGRATE)       │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘ │
└─────────┼─────────────────┼─────────────────┼──────────────────┼────────────┘
          │  HTTP/REST       │  HTTP/REST       │  HTTP/REST        │ HTTP/REST
          │                  │                  │                   │
┌─────────▼──────────────────▼──────────────────▼───────────────────▼──────────┐
│                     AISOC API GATEWAY  (FastAPI / port 8000)                  │
│                                                                               │
│  /api/v1/alerts  /api/v1/cases  /api/v1/compliance  /api/v1/connectors       │
│  /api/v1/rbac    /api/v1/tenants  /api/v1/playbooks  /api/v1/detection_rules │
│  /api/v1/investigations  /api/v1/hunts  /api/v1/graph  /api/v1/metrics       │
│  /auth/oidc/*    /auth/saml/*    /graphql  /ws (WebSocket)                   │
└──────┬──────────────┬──────────────┬──────────────┬──────────────┬───────────┘
       │              │              │              │              │
┌──────▼──────┐ ┌──────▼──────┐ ┌────▼──────┐ ┌────▼──────┐ ┌────▼──────────┐
│  AGENTS svc │ │  FUSION svc │ │  UEBA svc │ │THREATINTEL│ │  ACTIONS svc  │
│  LangGraph  │ │ FusionEngine│ │  Welford  │ │  MISP/OTX │ │  Dry-run,     │
│  Swarm      │ │ ClickHouse  │ │  Scoring  │ │  TAXII    │ │  Blast-radius │
│  LiteLLM    │ │ lake writer │ │  PEER grp │ │  Qdrant   │ │  Approval SLA │
└──────┬──────┘ └──────┬──────┘ └────┬──────┘ └────┬──────┘ └───────────────┘
       │               │             │              │
┌──────▼───────────────▼─────────────▼──────────────▼──────────────────────────┐
│                          INGEST SERVICE (Go)                                  │
│         OCSF Normaliser → Kafka → Neo4j Graph Writer (UNWIND MERGE)          │
└──────┬────────────────────────────────────────────────────────────────────────┘
       │
┌──────▼────────────────────────────────────────────────────────────────────────┐
│  INFRASTRUCTURE LAYER                                                         │
│  PostgreSQL (RLS) │ Redis (Bloom/UEBA) │ Kafka/ZK │ ClickHouse │ Neo4j       │
│  OpenSearch (IOC) │ Qdrant (vectors)   │ LiteLLM  │ Prometheus │ Grafana     │
└────────────────────────────────────────────────────────────────────────────────┘
          ↑
┌─────────┴──────────────────────────────────────────────────────────────────────┐
│  SUPABASE (Retained for WE auth + legacy data during migration period)        │
│  PostgreSQL + Auth + Realtime                                                  │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Data Flow Notes:**
1. WE frontend makes REST calls to AiSOC API Gateway for migrated modules
2. AiSOC API proxies investigation calls to `agents` service (SSRF-guarded)
3. Ingest service normalises events from WE's existing connectors via OCSF
4. Supabase is retained during migration as auth provider; AiSOC issues its own JWTs
5. Realtime service pushes graph updates to WE frontend via WebSocket

---

## 8. API Integration Plan

### 8.1 Authentication Bridge

AiSOC issues its own JWTs after OIDC/SAML. During initial integration, use AiSOC's
local JWT auth with API keys:

```typescript
// In WE frontend — replace Supabase client calls with AiSOC client
import { AiSOCClient } from "@aisoc/sdk"; // packages/sdk-ts

const aisoc = new AiSOCClient({
  baseUrl: process.env.AISOC_API_URL,      // http://aisoc-api:8000
  token: process.env.AISOC_API_TOKEN,      // JWT or aisoc_… API key
});
```

The TypeScript SDK in `packages/sdk-ts/` provides auto-generated types from
`docs/openapi.yaml` and ergonomic request builders.

**API key creation:**
```http
POST /api/v1/api_keys
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{
  "name": "wadjet-eye-integration",
  "scopes": ["alerts:read", "alerts:write", "cases:read", "cases:write",
             "investigations:read", "investigations:write", "ueba:read",
             "threat_intel:read", "compliance:read", "compliance:write"]
}
```

### 8.2 Alert Integration

**Current WE flow:** Browser JS → Supabase `INSERT INTO alerts`
**Target flow:** Browser/backend → `POST /api/v1/alerts`

```typescript
// Example: submit an alert from WE frontend
const alert = await aisoc.alerts.create({
  title: "Suspicious PowerShell Execution",
  severity: "high",
  source: "crowdstrike",
  raw_event: ocsfNormalisedEvent,    // Must be OCSF format for fusion scoring
  mitre_techniques: ["T1059.001"],
});
// AiSOC returns: fused alert with dedup_key, confidence_score, entity_risk
```

**OCSF transformation helper** (wrap existing WE alert format):
```typescript
function toOcsf(weAlert: WEAlert): OcsfEvent {
  return {
    class_uid: 2004,          // Detection Finding
    class_name: "Detection Finding",
    category_uid: 2,          // Findings
    activity_id: 1,           // Create
    severity_id: severityMap[weAlert.severity],
    time: weAlert.created_at,
    metadata: {
      version: "1.1.0",
      product: { name: "Wadjet-Eye", vendor_name: "Wadjet-Eye AI" },
    },
    tenant_uid: currentUser.tenant_id,
    // ... map remaining fields
  };
}
```

### 8.3 Investigation Integration

**Current WE flow:** `nexus.js` calls OpenAI directly, result rendered in UI
**Target flow:** WE cases page → `POST /cases/{id}/investigate` → AiSOC agents proxy

```typescript
// Trigger investigation (WE cases.js)
const response = await aisoc.cases.investigate(caseId, {
  streaming: true,
});

// Stream investigation steps via WebSocket
const ws = new WebSocket(`${AISOC_WS_URL}/ws/investigations/${runId}`);
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === "step") {
    // Append to WE's investigation timeline UI
    appendInvestigationStep(msg.agent, msg.summary, msg.kind);
  }
  if (msg.type === "done") {
    renderInvestigationReport(msg.state.report_md);
  }
};
```

The agents proxy in `cases.py` uses `_SAFE_PROXY_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./%]*$")`
to guard against SSRF — only alphanumeric relative paths are forwarded to `http://agents:8084`.

### 8.4 UEBA Integration

**Target flow:** WE identity panel → `GET /api/v1/ueba/anomalies`

```typescript
// Fetch UEBA anomalies for entity
const anomalies = await aisoc.ueba.listAnomalies({
  entityType: "user",
  entityId: "jsmith@corp.com",
  minRiskLevel: "medium",
  limit: 50,
});

// Score an event (for real-time feedback)
const result = await aisoc.ueba.scoreEvent({
  entityType: "user",
  entityId: "jsmith@corp.com",
  eventType: "login",
  features: {
    login_hour: 3,           // 3am — unusual
    failed_attempts: 5,
    geo_distance_km: 8500,   // Different continent
  },
  peerGroupId: "finance-team",
});
// Returns: { composite_score: 7.4, risk_level: "critical", peer_deviation: 3.2 }
```

### 8.5 Threat Intelligence Integration

```typescript
// IOC enrichment (replaces WE's manual lookup)
const iocResult = await aisoc.threatIntel.enrichIoc({
  value: "185.220.101.45",
  type: "ip",
});
// Returns: { malicious: true, confidence: 0.94, actors: ["Sandworm"],
//            sources: ["OTX", "CISA-KEV"], last_seen: "2026-07-20T14:22:00Z" }

// Actor attribution
const actor = await aisoc.threatIntel.getActorAttribution("Sandworm");
// Returns: techniques[], campaigns[], targets[], infrastructure[]
```

### 8.6 Compliance Integration

```typescript
// Collect evidence (tamper-evident hash chain)
const evidence = await aisoc.compliance.collectEvidence({
  framework: "SOC2",
  control: "CC7.2",            // System Monitoring
  summary: "Alert investigation completed for INC-042",
  rawPayload: { case_id: caseId, investigation_run_id: runId },
  caseId: caseId,
});
// Returns: { id, payload_hash, prev_hash, created_at }
// SHA-256 chain: hash = sha256(prev_hash + summary + raw_payload)

// Generate compliance posture report
const report = await aisoc.compliance.getReport({
  framework: "PCI-DSS",
  dateRange: { from: "2026-01-01", to: "2026-07-21" },
});
```

### 8.7 CORS and Proxy Configuration

AiSOC's FastAPI API gateway must be configured to accept requests from the WE frontend origin:

```python
# In AiSOC services/api/app/main.py — add CORS middleware
app.add_middleware(
  CORSMiddleware,
  allow_origins=[os.getenv("WADJET_EYE_ORIGIN", "https://app.wadjet-eye.com")],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["Authorization", "Content-Type"],
)
```

Alternatively, run AiSOC API behind an nginx reverse proxy co-located with WE's static file
server to avoid CORS entirely:

```nginx
# nginx.conf snippet
location /aisoc/ {
    proxy_pass http://aisoc-api:8000/;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Tenant-ID $http_x_tenant_id;
}
```

---

## 9. AI Architecture Assessment

### 9.1 AiSOC LLM Architecture

AiSOC implements a **layered, defence-in-depth LLM architecture** with six distinct
security and quality controls:

```
Alert → LLMInputContract → make_chat_model(role) → LiteLLM Gateway → Provider
         (fail-closed)      (task alias)          (alias router)    (GPT-4o etc.)
```

#### Layer 1: LLMInputContract (Security)
Source: `services/agents/app/llm/contract.py`

The contract is a **fail-closed heuristic validator** that blocks prompts containing:
- OCSF keys: `class_uid`, `category_uid`, `activity_id`, `type_uid`, `metadata`,
  `time_dt`, `observables`, `raw_data`
- Raw log keys: `Event`, `EventData`, `Sysmon`, `RecordID`, `_raw`, `_time`, `punct`
- Secret patterns: `api_key=`, `password:`, `-----BEGIN ... PRIVATE KEY-----`
- Oversized messages: > 60,000 characters (configurable via `AISOC_AGENTS_LLM_CONTRACT_MAX_CHARS`)
- Logs embedded in JSON: array of dicts with > 6 keys matching log signatures

**Design decision:** False positives (blocking a benign message) are preferred over
false negatives (leaking raw log data). Enforcement can be disabled for debugging via
`AISOC_AGENTS_LLM_CONTRACT_ENFORCED=0`.

**Recommendation for Wadjet-Eye:** Port `LLMInputContract.validate()` logic to WE's
existing GPT call sites in `nexus.js` or any server-side edge functions. This is the
single highest-value security improvement from AiSOC.

#### Layer 2: Task Alias Routing (Operational)
Source: `infra/litellm/config.yaml`

7 distinct task aliases map to cost-optimised models:
```yaml
aisoc-triage:      gpt-4o-mini   # High-volume, cheap+fast
aisoc-investigation: gpt-4o      # Deep reasoning — stronger model
aisoc-report:      gpt-4o        # Quality-focused write-ups
aisoc-recon:       gpt-4o-mini
aisoc-copilot:     gpt-4o-mini
aisoc-summary:     gpt-4o-mini
aisoc-nl:          gpt-4o-mini
```

Operators swap any alias to Ollama/vLLM without code changes — only config. This is
critical for WE's enterprise customers who require on-premise LLM deployment.

#### Layer 3: Dual LangGraph Pipelines (Orchestration)

**Graph 1 — Triage Pipeline** (`workflow.py`):
```
auto_triage ─┬─ (high-confidence FP/benign) ──► END
              └─ (else) ──► triage ──► enrichment ──► investigation ──► attack_path ──► END
```
- Conditional early exit prevents wasted LLM spend on clear false positives
- `AgentStatus.COMPLETED` at any node terminates the graph
- Pydantic `InvestigationState` threaded through all nodes

**Graph 2 — Investigator Pipeline** (`orchestrator.py`):
```
START ──► recon ──► forensic ──► responder ──► report_writer ──► END
               ↘ (failed/completed) ──────────────────────────► END
```
- `_safe_node` wrapper catches all exceptions, emits OTel span, marks state as failed
  rather than crashing the graph
- `_guard` conditional edge skips remaining nodes if state is terminal
- Full streaming via `InvestigatorOrchestrator.stream()` with monotonic seq de-duplication

#### Layer 4: Hypothesis Swarm (Parallel Reasoning)

Source: `services/agents/app/swarm/swarm.py`

```python
results = await asyncio.gather(*[_agent(h, signal, per_agent_budget) for h in chosen])
```

Up to 5 competing hypotheses run concurrently. Each is capped at 1,500 tokens
(`DEFAULT_PER_AGENT_TOKEN_BUDGET`). Deterministic keyword+technique scoring:
```python
score = max(0.0, min(1.0,
    min(len(evidence) * 0.25, 0.6) +      # keyword component (max 0.6)
    min(len(tech_hits) * 0.3, 0.5) -      # technique component (max 0.5)
    min(len(contradictions) * 0.3, 0.6)    # contradiction penalty (max 0.6)
))
```

**Key design:** Current implementation is deterministic (no live LLM calls in `_evaluate`).
This means `run_swarm_sync()` works without any API key for CI/testing.

#### Layer 5: Append-Only Audit Ledger

Source: `services/api/app/models/investigation.py`

```python
class InvestigationEvent(Base):
    # One row per agent step. Append-only - SQL migration enforces immutability.
    input_hash:   Mapped[str | None]    # SHA-256 of input state
    output_hash:  Mapped[str | None]    # SHA-256 of output state
    duration_ms:  Mapped[int]
    seq:          Mapped[int]           # Monotonic sequence number
```

The SQL migration (`008_investigation_ledger.sql`) adds an immutability trigger that
prevents UPDATE or DELETE on `investigation_events`. This satisfies SOC 2 CC8.1 (Change
Management) and ISO 27001 A.12.4.2 (Protection of Log Information).

#### Layer 6: Cost Tracking

Source: `services/agents/app/core/cost_telemetry.py`

`CostTracker` context manager tracks token usage and USD cost per investigation run,
stores in `investigation_runs.total_cost_usd`, and exports to Prometheus for budget
alerting. WE has no equivalent cost governance.

### 9.2 Comparison: AiSOC AI vs Wadjet-Eye AI

| Dimension | Wadjet-Eye Current | AiSOC |
|---|---|---|
| Agent orchestration | Single GPT call per action | LangGraph dual graph + swarm |
| Streaming | None (polling) | WebSocket per-step streaming |
| Input validation | None | Fail-closed LLMInputContract |
| Model flexibility | OpenAI only | LiteLLM gateway (any provider) |
| Audit trail | None | Append-only immutable ledger with hashes |
| Cost governance | None | Per-run token + USD tracking |
| Early exit | None | Conditional edge at auto_triage |
| Error handling | Unhandled JS exceptions | `_safe_node` OTel-instrumented wrapper |
| OTel tracing | None | Per-node spans with `case_id`, `tenant_id`, cost |

**Verdict:** AiSOC's AI architecture is 2–3 generations ahead of WE's current implementation.
The integration recommendation is to adopt AiSOC's agents service wholesale and retire
browser-side GPT calls.

---

## 10. Infrastructure Assessment

### 10.1 Full-Stack Infrastructure Requirements

Running AiSOC's complete docker-compose.yml requires:

| Component | Image | RAM (approx) | Purpose |
|---|---|---|---|
| PostgreSQL 16 | `postgres:16` | 512 MB | Primary data store, RLS |
| Redis 7 | `redis:7-alpine` | 256 MB | Cache, Bloom filter, UEBA signal bus |
| Zookeeper | `confluentinc/cp-zookeeper:7.5.0` | 256 MB | Kafka coordination |
| Kafka | `confluentinc/cp-kafka:7.5.0` | 1 GB | Event backbone |
| Kafka UI | `provectuslabs/kafka-ui` | 256 MB | Dev tooling |
| ClickHouse | `clickhouse/clickhouse-server:24.3` | 2 GB | Event lake (OLAP) |
| OpenSearch | `opensearchproject/opensearch:2.12.0` | 2 GB | IOC full-text search |
| Qdrant | `qdrant/qdrant:v1.8.4` | 512 MB | Vector embeddings |
| Neo4j | `neo4j:5.18-community` | 1 GB | Entity graph, attack paths |
| LiteLLM | custom | 256 MB | LLM gateway |
| api | custom Python | 512 MB | REST API |
| agents | custom Python | 512 MB | LangGraph orchestration |
| ingest | custom Go | 256 MB | OCSF normalisation, Neo4j write |
| fusion | custom Python | 512 MB | Alert dedup/correlation |
| threatintel | custom Python | 512 MB | Feed polling |
| ueba | custom Python | 256 MB | Anomaly scoring |
| actions | custom Python | 256 MB | Automated response |
| connectors | custom Python | 512 MB | 78 source integrations |
| realtime | custom Node.js | 256 MB | WebSocket bus |
| Prometheus | `prom/prometheus` | 256 MB | Metrics collection |
| Grafana | `grafana/grafana` | 256 MB | Metrics dashboards |
| **Total (estimate)** | | **~12–14 GB RAM** | |

**Operational reality:** Running the full stack requires a dedicated server or
Kubernetes cluster with ≥16 GB RAM. This is a significant operational step up
from WE's current Supabase-hosted model.

### 10.2 Lite Integration Stack (Recommended for Phase 1)

For initial integration, only 5 services are required:

```yaml
services:
  postgres:    # RLS, cases, alerts, RBAC
  redis:       # Dedup + session cache
  litellm:     # LLM gateway
  api:         # REST API gateway
  agents:      # LangGraph investigation engine
```

**Estimated RAM:** ~3 GB. **Setup time:** < 30 minutes with provided docker-compose.

Expand to full stack incrementally as each module is integrated.

### 10.3 Deployment Target Options

AiSOC provides first-class deployment configs for:

| Platform | Config Location | Effort |
|---|---|---|
| Docker Compose | `docker-compose.yml` | Low |
| Kubernetes + Helm | `infra/helm/aisoc/` (Chart v5.2.0) | Medium |
| Terraform + AWS EKS | `infra/terraform/` (VPC + EKS + RDS + MSK + ElastiCache + OpenSearch) | High |
| Terraform + Azure | `infra/terraform/azure/` | High |
| Fly.io | `infra/fly/` | Low |
| Render | `render.yaml` | Low |
| Coolify | `infra/coolify/` | Low |

**Recommendation:** Start with Docker Compose on a dedicated VM (≥4 vCPU, 16 GB RAM).
Migrate to Kubernetes when tenant count justifies horizontal scaling.

### 10.4 Observability Stack

AiSOC ships a complete observability stack:
- **Prometheus** scrapes all services; LiteLLM exports cost + latency + error metrics
- **Grafana** dashboards for all services
- **OpenTelemetry** traces per investigation node (exported from `_safe_node` wrapper)
- **Structured logging** via `structlog` with JSON output

SLOs are defined in `docs/operations/slos.yaml` with a CI coverage gate.

### 10.5 Data Storage Requirements

| Data Store | Purpose | Growth Rate (estimate) |
|---|---|---|
| PostgreSQL | Cases, alerts, RBAC, investigations, compliance | ~10 GB/month (active SOC) |
| ClickHouse | Raw event lake (OLAP) | ~100 GB/month (1K events/sec) |
| OpenSearch | IOC index | ~5 GB/month |
| Qdrant | Embedding vectors | ~2 GB/month |
| Neo4j | Entity graph | ~20 GB/month |
| Redis | Cache (bounded) | ~1 GB static |

**Hot/cold tiering:** AiSOC Phase D2 implements `llm-*` detections + hot/cold ClickHouse
tiering. Events > 90 days move to cold storage automatically.

---

## 11. Migration Roadmap (5 Phases)

### Phase 1 — Foundation & Investigation (Weeks 1–3)

**Goal:** Deploy AiSOC API + agents + LiteLLM. Replace browser-side GPT calls in
Wadjet-Eye's Nexus AI Copilot with AiSOC investigation API.

**Deliverables:**
1. Deploy AiSOC lite stack (PostgreSQL + Redis + LiteLLM + `api` + `agents`) via Docker Compose
2. Configure LiteLLM gateway with WE's OpenAI API key
3. Create AiSOC tenant + API key for WE integration
4. Update `js/nexus.js`:
   - Replace `callOpenAI()` / direct GPT calls with `aisoc.cases.investigate()`
   - Implement WebSocket stream handler for investigation steps
   - Add investigation ledger viewer (read from `GET /api/v1/investigations/{run_id}`)
5. Port `LLMInputContract` validation to any remaining direct LLM calls
6. Deploy CORS middleware or nginx proxy

**Success criteria:**
- Investigation launched from WE UI streams steps in real time
- Each step stored in AiSOC's immutable ledger
- Total investigation cost visible in WE UI
- No raw alert data reaches LLM (LLMInputContract enforced)

**Migration difficulty:** Medium (API integration; no schema migration yet)
**Risk:** Low (WE retains fallback to existing GPT calls during transition)

---

### Phase 2 — Alert Fusion & UEBA (Weeks 4–7)

**Goal:** Replace Supabase alert inserts with AiSOC's FusionEngine. Activate UEBA
anomaly scoring.

**Deliverables:**
1. Add `fusion/` and `ueba/` services to deployed stack
2. Add Kafka + Redis for fusion pipeline
3. Write OCSF transformation adapter for WE's existing alert format
4. Update WE alert creation flow to `POST /api/v1/alerts` (AiSOC)
5. Update WE alert list UI to `GET /api/v1/alerts` with fusion metadata:
   - `dedup_key` — collapsed duplicate display
   - `confidence_score` — fusion-derived confidence badge
   - `entity_risk_score` — entity-level risk badge
6. Integrate UEBA anomalies into WE's Identity Intelligence panel:
   - `GET /api/v1/ueba/anomalies?entity_type=user&entity_id=...`
   - Display Welford baseline deviation and peer-group comparison
7. Migrate existing WE alert history to AiSOC via batch OCSF import

**Success criteria:**
- Duplicate alerts collapsed by `dedup_key` in WE UI
- UEBA anomaly scores visible in identity panel
- ClickHouse event lake receiving all alert data
- 0 alerts lost during migration

**Migration difficulty:** High (requires OCSF transformation layer + Supabase data migration)
**Risk:** Medium (alert data is critical; run dual-write period for 2 weeks)

---

### Phase 3 — Threat Intelligence & Case Management (Weeks 8–11)

**Goal:** Deploy AiSOC threat intelligence pipeline. Migrate case management from
Supabase to AiSOC.

**Deliverables:**
1. Add `threatintel/` service + OpenSearch + Qdrant to stack
2. Configure MISP and OTX API keys (or CISA KEV only for air-gapped start)
3. Replace WE's manual IOC lookups with `GET /api/v1/threat_intel/iocs/enrich`
4. Populate WE's threat actor panel from `GET /api/v1/threat_intel/actors`
5. Migrate case schema:
   - Export existing WE cases from Supabase
   - Import via `POST /api/v1/cases` with tenant scoping
   - Update WE `js/cases.js` to call AiSOC cases API
6. Enable MITRE ATT&CK coverage mapping per case
7. Activate compliance evidence collection:
   - Every case closure → `POST /api/v1/compliance/evidence`
   - SOC 2 CC7.2 evidence auto-collected from investigation runs

**Success criteria:**
- IOC enrichment returns results within 500ms (Redis-cached)
- All cases accessible from AiSOC cases API
- Case state machine enforces `new → triaged → ... → closed` forward-only transitions
- SHA-256 evidence hash chain verifiable for last 90 days of cases

**Migration difficulty:** High (case data migration + state machine adoption)
**Risk:** Medium (forward-only state machine rejects any backward transitions — requires
WE UI workflow audit first)

---

### Phase 4 — RBAC, Connectors & Detection Rules (Weeks 12–15)

**Goal:** Migrate RBAC backend to AiSOC schema. Activate connector pipeline. Deploy
detection rule evaluation.

**Deliverables:**
1. Migrate RBAC:
   - Export WE roles/permissions from Supabase
   - Import into AiSOC `permissions` + `roles` + `role_permissions` tables
   - Update `js/rbac.js` to call `/api/v1/rbac/*`
   - Retain WE's RBAC Admin UI (it already works post PR #191)
2. Activate AiSOC connectors for existing WE data sources:
   - Map WE's existing connector stubs to AiSOC plugin implementations
   - Configure per-connector secrets via AiSOC credential resolver
   - Enable runtime conformance gate (Phase 10 hardening)
3. Deploy detection rules:
   - Ingest curated 417 detections from `marketplace/curated.json`
   - Enable `DetectionEngine` in fusion pipeline
   - Wire detection hits to WE's Campaigns/Detections panel
4. Migrate MSSP tenancy if WE supports managed security customers:
   - Configure `parent_tenant_id` on child tenants
   - Enable `/api/v1/mssp/*` endpoints

**Success criteria:**
- All WE roles/permissions functional via AiSOC RBAC API
- At least 1 connector actively ingesting events via OCSF pipeline
- Detection rules firing on live event stream
- MSSP admin can manage child tenants (if applicable)

**Migration difficulty:** High (RBAC data migration + connector re-wiring)
**Risk:** Low for RBAC (schema is well-defined). Medium for connectors (vendor API compatibility)

---

### Phase 5 — Playbooks, Compliance, and Production Hardening (Weeks 16–20)

**Goal:** Activate SOAR playbooks, compliance reporting, honeytoken deployment.
Harden for production.

**Deliverables:**
1. Import AiSOC's 62 playbooks into WE's SOAR panel
2. Wire playbook execution to `POST /api/v1/playbooks/{id}/run`
3. Enable Actions service with dry-run policy and blast-radius checks
4. Activate compliance dashboard:
   - Select applicable frameworks (SOC 2, ISO 27001, PCI-DSS)
   - Configure evidence auto-collection hooks
5. Deploy honeytokens for critical assets
6. Enable purple team coverage gaps report
7. Configure OIDC SSO (if enterprise customers require it):
   - Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`
   - Configure `JWT_SECRET` (non-default — OIDC implementation blocks default value)
8. Production hardening:
   - Enable all AiSOC monitoring (Prometheus + Grafana)
   - Configure alert routing (Slack-bot or Teams-bot)
   - Set up database backup/restore (tested in AiSOC Phase 3 hardening)
   - Configure ClickHouse hot/cold tiering

**Success criteria:**
- At least 3 automated playbooks executing without manual trigger
- Compliance evidence hash chain verified by external reviewer
- Honeytoken alert fires within 60 seconds of use
- OIDC login working for enterprise tenant
- All AiSOC SLOs in `docs/operations/slos.yaml` within bounds

**Migration difficulty:** Medium (configuration-heavy, no major data migrations)
**Risk:** Low (Phase 5 is additive; existing functionality unaffected)

---

## 12. Risk Assessment

### 12.1 Technical Risks

| Risk | Severity | Probability | Mitigation |
|---|---|---|---|
| OCSF transformation loses alert fidelity | High | Medium | Dual-write period in Phase 2; automated diff comparison of WE alerts vs AiSOC fused alerts |
| AiSOC state machine rejects existing case states | High | Low | Audit WE cases DB before migration; map non-standard states to `new` before import |
| LiteLLM gateway adds latency to investigation calls | Medium | Medium | Benchmark: LiteLLM adds ~20–50ms; acceptable for async investigation. Not acceptable for interactive copilot — use direct model for copilot path |
| Kafka event ordering guarantees under high load | Medium | Low | AiSOC Phase 5 hardening added event-time watermarking + idempotency. Risk is low for WE's event volume at launch |
| Neo4j memory pressure on large entity graphs | Medium | Medium | Start with `neo4j:5.18-community` (2 GB heap); upgrade to Enterprise if graph > 10M nodes |
| Redis Bloom filter false positive rate | Low | Low | Default false positive rate 1/1000; at WE's event volume this is acceptable. Monitor via `threatintel_iocs_ingested_total` Prometheus counter |
| ClickHouse storage growth at high event volume | Medium | Medium | Phase D2 hot/cold tiering mitigates; monitor via `docs/operations/slos.yaml` storage SLO |

### 12.2 Operational Risks

| Risk | Severity | Probability | Mitigation |
|---|---|---|---|
| 27-container stack complexity vs WE's zero-infra model | High | High | Start with 5-container lite stack; expand incrementally. Staff training on Kafka/Neo4j required. |
| AiSOC upstream API breaking changes | Medium | Low | AiSOC Phase 11 hardening added OpenAPI breaking-change detector + drift gate. SDK auto-generated from spec. Monitor `CHANGELOG.md`. |
| Cost overrun from GPT-4o investigation calls | Medium | Medium | `CostTracker` + Prometheus metric `aisoc_investigation_cost_usd`. Set budget alerts in Grafana. Route `aisoc-triage` to `gpt-4o-mini` (already default). |
| PostgreSQL RLS misconfiguration | Critical | Low | AiSOC's Phase 1 hardening closed cross-store tenant isolation. Use AiSOC's provided migration SQL (`002_rls.sql`); never manually edit RLS policies. |
| LLM prompt injection via malicious alert data | High | Medium | `LLMInputContract` mitigates. Additionally, AiSOC Phase 1 hardening added prompt injection gates (Phase 1: four existential holes). |

### 12.3 Security Risks

| Risk | Severity | Probability | Mitigation |
|---|---|---|---|
| Default JWT secret (`changeme-insecure-default`) | Critical | Low | AiSOC's OIDC implementation explicitly refuses to sign tokens with this value. Set `JWT_SECRET` in production. |
| GraphiQL introspection in production | High | Low | AiSOC disables GraphiQL in non-dev environments via `is_dev_env()` check. Never set `APP_ENV=development` in production. |
| SSRF via agents proxy | High | Low | `_SAFE_PROXY_PATH_RE` allowlist in `cases.py` prevents scheme injection and path traversal. Do not modify this regex. |
| Kafka topic access control | Medium | Medium | Configure Kafka ACLs in production (not set in default compose). Each service should have per-topic produce/consume permissions. |
| OpenSearch cluster exposed without auth | High | Medium | Enable OpenSearch security plugin in production (`plugins.security.disabled: false`). Default compose disables security for dev convenience. |

### 12.4 Business Risks

| Risk | Severity | Probability | Mitigation |
|---|---|---|---|
| Migration disrupts existing WE customers | High | Medium | Feature-flag all AiSOC integrations. Route new tenants to AiSOC; existing tenants keep Supabase path during migration. |
| AiSOC repository abandonment (MIT, open-source) | Low | Low | MIT license + full source code mitigates vendor lock-in completely. Fork and maintain internally if upstream stalls. |
| Infrastructure cost increase ($300–$500/month for VM) | Medium | High | Offset by eliminating per-call GPT cost at scale (AiSOC batches and caches); UEBA eliminates alert fatigue = analyst time savings. |

---

## 13. Final Recommendation

### 13.1 Overall Verdict: **Selective API Integration — Recommended**

AiSOC v7.6.0 is a well-engineered, MIT-licensed platform with production-grade
implementations of five capabilities Wadjet-Eye currently lacks or implements inadequately:
AI investigation orchestration, UEBA anomaly detection, threat intelligence feeds, alert
fusion/correlation, and compliance evidence management.

**Do not attempt a wholesale replacement.** The two systems operate at different
architectural tiers. AiSOC is a backend microservices platform; Wadjet-Eye is a frontend
SPA. They are complementary, not competitive.

### 13.2 Module-Level Verdicts (Summary)

**REPLACE backend, keep WE frontend:**
- Alert management → AiSOC FusionEngine + `/api/v1/alerts`
- Case management → AiSOC case lifecycle API + observable graph
- AI investigation → AiSOC LangGraph dual-graph + swarm
- UEBA → AiSOC Welford baseline + RSS composite scorer
- Threat intelligence feeds → AiSOC MISP/OTX/CISA-KEV/TAXII pipeline
- Playbooks/SOAR → AiSOC 62 playbooks + actions service
- Connectors → AiSOC 78 plugins (replace WE manual stubs)
- RBAC backend schema → AiSOC PG RLS + tenant-scoped roles
- Compliance evidence → AiSOC SHA-256 tamper-evident hash chain

**INTEGRATE (consume AiSOC API from WE frontend):**
- Detection rules → AiSOC 417 curated + live DetectionEngine
- Threat hunting → AiSOC NL→KQL/SPL/ES|QL translator + saved hunts
- Identity graph → AiSOC Neo4j-backed identity timeline
- Attack chain analysis → AiSOC fuse-time chain grouper + Neo4j
- EASM/Posture → AiSOC effective-permissions + autopilot scorecard
- Realtime events → AiSOC WebSocket bus

**KEEP (WE has no replacement candidate):**
- Global Cyber Threat Map (D3.js/TopoJSON, PR #192) — unique UI differentiator
- CDWIE / WS1–WS10 workspace modules — custom interactive visualisations
- Supabase Auth — retain during transition; migrate to OIDC only if SSO is required
- Custom SOC UI aesthetic, KPI cards, sparklines, radar charts

**IGNORE (net-new capabilities — deploy when ready):**
- Honeytokens — deploy in Phase 5 for zero-false-positive detection
- Purple team — deploy in Phase 5 for detection coverage validation
- MCP server — deploy for Cursor AI integration if developer tooling is a priority

### 13.3 Adoption Priority Order

1. **Highest priority — LLMInputContract:** The fail-closed data validation pattern
   should be ported immediately, independent of any AiSOC deployment. It is a pure
   security improvement to WE's existing GPT calls.

2. **High priority — Investigation Pipeline:** Replace browser-side GPT calls with
   AiSOC's LangGraph investigator. This is the single highest-value capability
   exchange (streaming, audit ledger, cost control, provider agnosticism).

3. **High priority — Alert Fusion:** WE has no deduplication or correlation. At scale,
   alert fatigue will become a critical UX problem. FusionEngine solves it.

4. **Medium priority — Threat Intelligence:** MISP/OTX/CISA-KEV polling significantly
   enriches IOC quality. Deploy after fusion is stable.

5. **Medium priority — UEBA:** Welford baseline anomaly detection adds a detection layer
   that requires no rules. Deploy when identity intelligence module is ready.

6. **Lower priority — Compliance:** Deploy compliance evidence hash chain before any
   enterprise sales requiring SOC 2 or ISO 27001 attestation.

---

## 14. Action Plan

### Immediate Actions (This Week)

#### Action 1: Port LLMInputContract to Wadjet-Eye (1–2 days)
**Owner:** Frontend/Backend engineer
**Files to modify:** Any WE JS/TS files that call OpenAI directly (primarily `nexus.js`)
**Specific steps:**
1. Read `services/agents/app/llm/contract.py` — extract `_OCSF_KEYS`, `_LOG_KEYS`,
   `_LOG_SHAPE_PATTERNS`, `_SECRET_PATTERNS` regex lists
2. Port `classify_message()` function to a WE utility (TypeScript or Supabase Edge Function):
   ```typescript
   function classifyLLMMessage(content: string): string | null {
     if (content.length > 60000) return "message_too_long";
     const OCSF_KEYS = ["class_uid","activity_id","type_uid","raw_data","time_dt"];
     if (OCSF_KEYS.some(k => content.includes(`"${k}"`))) return "ocsf_key_detected";
     if (content.includes('"_raw"') || content.includes('"sourcetype"')) return "log_key_detected";
     if (/-----BEGIN.*PRIVATE KEY-----/.test(content)) return "secret_detected";
     return null;
   }
   ```
3. Wrap all `openai.chat.completions.create()` calls with this validator
4. Log violations to console + optionally to Supabase audit table

**Expected outcome:** Raw alert data and OCSF events no longer reach OpenAI.

#### Action 2: Evaluate Lite Stack Deployment (2–3 days)
**Owner:** DevOps / Platform engineer
**Steps:**
1. Clone AiSOC repo to a staging VM (≥4 vCPU, 8 GB RAM):
   ```bash
   git clone https://github.com/beenuar/AiSOC.git
   cd AiSOC
   ```
2. Create lite docker-compose override (`docker-compose.lite.yml`):
   ```yaml
   services:
     postgres:
       image: postgres:16
     redis:
       image: redis:7-alpine
     litellm:
       build: infra/litellm/
     api:
       build: services/api/
       environment:
         OPENAI_BASE_URL: http://litellm:4000/v1
         OPENAI_API_KEY: ${LITELLM_MASTER_KEY}
     agents:
       build: services/agents/
   ```
3. Run `docker compose -f docker-compose.lite.yml up`
4. Verify API health: `curl http://localhost:8000/api/v1/health`
5. Create test tenant and API key
6. Run AiSOC's CI test suite: `make test-integration`

#### Action 3: Spike Investigation API from WE (1 day, after Action 2)
**Owner:** Frontend engineer
**Steps:**
1. Install `@aisoc/sdk` from monorepo path
2. Create a WE feature branch `feat/aisoc-investigation-spike`
3. In `js/nexus.js`, add a `_triggerAiSOCInvestigation(alertId)` function:
   ```javascript
   async function _triggerAiSOCInvestigation(caseId) {
     const resp = await fetch(`${AISOC_API}/api/v1/cases/${caseId}/investigate`, {
       method: 'POST',
       headers: { 'Authorization': `Bearer ${AISOC_TOKEN}` },
     });
     const { run_id } = await resp.json();
     // Open WebSocket for streaming
     const ws = new WebSocket(`${AISOC_WS}/ws/investigations/${run_id}`);
     ws.onmessage = (e) => {
       const msg = JSON.parse(e.data);
       if (msg.type === 'step') _appendInvestigationStep(msg);
       if (msg.type === 'done') _renderReport(msg.state.report_md);
     };
   }
   ```
4. Call `_triggerAiSOCInvestigation` from WE's existing "Investigate" button
5. Verify streaming output in browser console

### Short-Term Actions (Weeks 1–4)

| # | Action | Owner | Week | Effort |
|---|---|---|---|---|
| 4 | Full Phase 1 deployment (Section 11 Phase 1 deliverables) | DevOps + FE | 1–3 | 3 person-weeks |
| 5 | OCSF transformation adapter for WE alert format | Backend | 2–3 | 3 days |
| 6 | Deploy FusionEngine + Kafka for alert dedup | DevOps | 3–4 | 2 days |
| 7 | Dual-write period: WE alerts → Supabase AND AiSOC | Backend | 3–6 | 1 week |
| 8 | Benchmark LiteLLM gateway latency vs direct OpenAI | DevOps | 2 | 1 day |
| 9 | Configure Prometheus + Grafana dashboards | DevOps | 3 | 1 day |

### Medium-Term Actions (Weeks 5–12)

| # | Action | Owner | Week | Effort |
|---|---|---|---|---|
| 10 | Phase 2 completion (UEBA + Fusion fully live) | All | 4–7 | 4 person-weeks |
| 11 | Phase 3 completion (ThreatIntel + Cases migrated) | All | 8–11 | 4 person-weeks |
| 12 | Audit WE cases DB for state machine compatibility | Backend | 7 | 2 days |
| 13 | Configure CISA KEV feed (no API key required) | DevOps | 5 | 1 day |
| 14 | Deploy compliance evidence collection for cases | Backend | 10 | 2 days |

### Long-Term Actions (Weeks 13–20)

| # | Action | Owner | Week | Effort |
|---|---|---|---|---|
| 15 | Phase 4: RBAC migration + connectors + detection rules | All | 12–15 | 4 person-weeks |
| 16 | Phase 5: Playbooks, compliance, hardening | All | 16–20 | 4 person-weeks |
| 17 | OIDC SSO configuration for enterprise tenants | Backend | 17 | 2 days |
| 18 | Honeytoken deployment for critical WE assets | Security | 18 | 1 day |
| 19 | Purple team coverage gap report | Security | 19 | 2 days |
| 20 | Decommission Supabase alert/case tables | DevOps | 20 | 1 day |

### Decision Checkpoints

**After Phase 1 (Week 3):** Evaluate LangGraph investigation quality vs current GPT
approach. If investigation quality is not superior, pause Phase 2 and investigate
root cause (likely LiteLLM misconfiguration or missing context bundle).

**After Phase 2 (Week 7):** Evaluate alert dedup rate from FusionEngine. Target:
> 30% alert volume reduction via deduplication. If below target, tune Correlator
window and Deduplicator Redis TTL.

**After Phase 3 (Week 11):** Evaluate threat intel enrichment hit rate on WE's
existing IOC universe. Target: > 50% of WE IOCs enriched by AiSOC ThreatIntel.
If below target, add MISP server or expand to OTX/TAXII feeds.

**After Phase 4 (Week 15):** Go/no-go decision for full Supabase migration.
At this point AiSOC should be handling all alert, case, RBAC, and connector data.
Supabase retained only for auth + static config.

---

## Appendix A: Key Files Reference

| Purpose | File Path |
|---|---|
| LLM security contract | `services/agents/app/llm/contract.py` |
| LangGraph triage pipeline | `services/agents/app/graph/workflow.py` |
| LangGraph investigator | `services/agents/app/investigator/orchestrator.py` |
| Hypothesis swarm | `services/agents/app/swarm/swarm.py` |
| LiteLLM gateway config | `infra/litellm/config.yaml` |
| Multi-tenant RLS | `services/api/app/db/rls.py` |
| Tenant + MSSP model | `services/api/app/models/tenant.py` |
| RBAC ORM models | `services/api/app/models/rbac.py` |
| Alert fusion engine | `services/fusion/app/main.py` |
| OCSF normaliser (Go) | `services/ingest/internal/normalizer/normalizer.go` |
| Neo4j graph writer (Go) | `services/ingest/internal/graph/writer.go` |
| UEBA scoring | `services/ueba/app/services/scoring.py` |
| UEBA Welford baseline | `services/ueba/app/services/baseline.py` |
| Threat intel feeds | `services/threatintel/app/main.py` |
| Case management API | `services/api/app/api/v1/endpoints/cases.py` |
| Investigation ledger ORM | `services/api/app/models/investigation.py` |
| Compliance evidence API | `services/api/app/api/v1/endpoints/compliance.py` |
| OIDC implementation | `services/api/app/auth/oidc.py` |
| SAML 2.0 implementation | `services/api/app/auth/saml.py` |
| Strawberry GraphQL schema | `services/api/app/graphql/schema.py` |
| TypeScript SDK | `packages/sdk-ts/` |
| Helm chart | `infra/helm/aisoc/Chart.yaml` |
| Terraform (AWS) | `infra/terraform/` |

---

*Report generated by AI Developer Agent — Genspark Platform*
*Based on static analysis of AiSOC repository (HEAD, 2026-07-21)*
*All citations reference actual source files read from `/home/user/aisoc-analysis/`*
