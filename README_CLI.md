# code-hunter — Unified CLI for Scan4Me + Oracle + OmniCLI

Single entry point for the full bug-bounty pipeline:

```
python3 code_hunter.py <group> <subcommand> [flags]
```

## 7 Command Groups

| Group | Purpose |
|-------|---------|
| `scan` | Scan4Me — discover + rank targets without credentials |
| `oracle` | Oracle — hunt pipeline with 3 mindset cages |
| `omni` | OmniCLI — red-team / orchestrate (independent of Oracle) |
| `omni build` | OmniCLI build mode — mindset-caged hybrid red-team + build |
| `config` | Shared config.json for Scan4Me + Oracle |
| `pipeline` | End-to-end money pipeline |
| `status` | Health check for all 3 systems |
| `report` | Consolidated hunt report |

---

## 1. SCAN — Scan4Me (no credentials needed)

```
python3 code_hunter.py scan sync                    # Fetch all platform feeds
python3 code_hunter.py scan radar --limit 10        # Ranked targets
python3 code_hunter.py scan export --top 20         # Export for recon
python3 code_hunter.py scan keys                    # Show API key status
python3 code_hunter.py scan check <domain>          # Verify in-scope
python3 code_hunter.py scan handoff                 # Generate Oracle P12 handoff
```

Platforms scanned without auth: HackerOne, Bugcrowd, Intigriti, YesWeHack,
Immunefi, Sherlock, PDPrograms, Bugbase, HackenProof, Cantina, Patchstack, Huntr.

---

## 2. ORACLE — Hunt Pipeline (3 Mindset Cages)

```
python3 code_hunter.py oracle prescan --sync        # P11: Scan4Me sweep
python3 code_hunter.py oracle scan -N 3 --download   # P11: verify + deep-dive + download
python3 code_hunter.py oracle queue --execute        # P12: execute hunts
python3 code_hunter.py oracle hunt <program>         # Single-target hunt
python3 code_hunter.py oracle bundle <workspace>     # Product bundle + SHA-256 manifest
python3 code_hunter.py oracle verify-download <zip> --json  # Integrity + submission gate
python3 code_hunter.py oracle status                 # Tools + models health
```

### Mindset Cages (hard constraints, not suggestions)

| Cage | Techniques | Scope |
|------|-----------|-------|
| **Mindset 1** | MITRE ATT&CK TTPs + offensive red teaming | In-scope assets only |
| **Mindset 2** | Paradoxes, impossible problems, iPhone framing, invisible seams | In-scope assets only |
| **Mindset 3** | Synthesis of M1 + M2 + invisible seam + red teaming | In-scope assets only |

A model in Mindset 1 that attempts Mindset 2 techniques fails loud. Mindset 3
refuses to synthesize without M1 + M2 inputs.

### Verification Cascade (per webpage fetch)

| Order | Method | No-Cloud? |
|-------|--------|-----------|
| 1 | CDP (logged-in Chromium port 9227) | No |
| 2 | Crawl4AI (local Playwright headless) | ✅ Yes |
| 3 | Jina Reader (cloud markdown) | No |
| 4 | Firecrawl (cloud, `FIRECRAWL_API_KEY` set) | No |
| 5 | Plain HTTP GET | ✅ Yes |

Every result carries a `via` provenance tag.

---

## 3. OMNI BUILD — Mindset-Caged Hybrid

Groq is the lead provider. Local folder is read first.

```
python3 code_hunter.py omni build "your idea"                        # default: split 50/50
python3 code_hunter.py omni build "idea" --mode sequential           # ALL M1 → ALL M2 → ALL M3
python3 code_hunter.py omni build "idea" --mode split --split-ratio 70  # 70% M1 / 30% M2 → ALL M3
python3 code_hunter.py omni build "idea" --mode all3                 # ALL providers M3 together
python3 code_hunter.py omni build "idea" --providers groq,openrouter,nvidia
```

**Execution modes:**
- `sequential` — All providers do Mindset 1 → All do Mindset 2 → All do Mindset 3
- `split` — X% do Mindset 1, rest do Mindset 2 → All do Mindset 3 (default 50%)
- `all3` — All providers do Mindset 3 together (synthesis only)

**Local folder first:** Before any model call, the workspace is indexed. Matching
files are shown to the user. If nothing matches locally, the user is warned and
the run proceeds to external providers with a FAIL-LOUD notice.

**Fail loud:** Any provider failure screams with `✗ FAIL LOUD` — never silent.

---

## 4. CONFIG — Shared config.json

One config at workspace root, auto-synced to `scan4me/config.json` and
`oracle/oracle.config.json`.

```
python3 code_hunter.py config --init       # Create shared config
python3 code_hunter.py config --show       # View it
python3 code_hunter.py config --sync       # Sync to both project dirs
python3 code_hunter.py config --set researcher.handle=name scan4me.filters.paid_bounties_only=true
```

---

## 5. PIPELINE — End-to-End Money Pipeline

```
python3 code_hunter.py pipeline --run --limit 50 --top-n 3 --no-cloud
```

**Steps (all wired together):**
1. **Scan4Me sync** — fetch feeds (no credentials)
2. **Oracle prescan** — P11 sweep → prescan report
3. **Oracle scan** — `-N` deep-dive + download workspaces
4. **Oracle queue --execute** — P12 execute hunts
5. **Report** — consolidated JSON report

**What's NOT yet in the auto-pipeline** (run manually if needed):
- `oracle bundle <workspace>` — package individual hunt workspace
- `oracle verify-download <bundle> --json` — integrity + submission gate
- `scan enrich --limit 30` — Bugcrowd official dates/metrics
- `scan check <domain>` — legal scope verification

---

## 6. STATUS & REPORT

```
python3 code_hunter.py status          # Health of all 3 systems
python3 code_hunter.py report          # Consolidated hunt report JSON
```

Report is written to `oracle/reports/CODE_HUNTER_REPORT.json` and includes:
- Latest handoff, scan, prescan, queue_state artifacts
- All downloaded workspaces (platform/slug)
- The 3 mindset cage definitions

---

## Design Decisions

| Decision | Implementation |
|----------|---------------|
| Hacker site API keys | Not required — use CDP/Playwright/Firecrawl/Plain GET cascade |
| Ollama / local model | Skipped — vestigial, not part of active design |
| Lead provider | Groq |
| Mindsets | Cages (hard constraints), not suggestions |
| Local-first | Read workspace before any model call |
| Fail loud | All errors scream visibly |
| Reports | Never auto-submitted (Oracle doctrine) — manual review only |

---

## Test Status

| System | Tests | Status |
|--------|-------|--------|
| Scan4Me | 121 | ✅ pass |
| Oracle | 1184 + 32 subtests | ✅ pass |
| OmniCLI | ~305 + 53 subtests | ⚠️ mostly (P4 gate needs qualifying run) |
