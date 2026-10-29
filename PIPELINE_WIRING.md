# Pipeline Wiring — What's Connected vs. What Needs Manual Steps

## Auto-Wired in `pipeline --run`

```
Step 1: scan4me sync              → code_hunter.py scan sync --no-cloud
Step 2: oracle prescan            → code_hunter.py oracle prescan --sync --limit 50 --no-cloud
Step 3: oracle scan               → code_hunter.py oracle scan -N 3 --download --no-cloud
Step 4: oracle queue --execute    → code_hunter.py oracle queue --execute --max-items 3 --no-cloud
Step 5: report                    → code_hunter.py report
```

All 5 steps are wired together in `cmd_pipeline()`. Each step's failure stops
the pipeline with a clear error message.

## NOT in Auto-Pipeline (run manually)

These need specific paths that the pipeline can't know ahead of time:

| Step | Command | Why manual |
|------|---------|------------|
| Bundle | `oracle bundle <workspace>` | Needs specific workspace path |
| Verify-download | `oracle verify-download <bundle.zip> --json` | Needs specific bundle path |
| Enrich | `scan enrich --limit 30` | Bugcrowd API enrichment, optional |
| Check scope | `scan check <domain>` | Needs specific domain |
| Keys | `scan keys` | Info-only, no action |

## Report Coverage

`code_hunter.py report` writes `oracle/reports/CODE_HUNTER_REPORT.json` with:

- `artifacts.handoff` — latest P12 handoff (verified programs, scores, payouts)
- `artifacts.scan` — latest scan report (count, verified count)
- `artifacts.prescan` — latest prescan report path
- `artifacts.queue_state` — latest queue state path
- `artifacts.workspaces` — all downloaded target workspaces (platform/slug)
- `mindsets` — the 3 mindset cage definitions

## Example Full Run

```bash
# 1. Initialize shared config (one-time)
python3 code_hunter.py config --init

# 2. Run the auto-pipeline
python3 code_hunter.py pipeline --run --limit 50 --top-n 3 --no-cloud

# 3. Bundle a specific workspace (manual - needs path)
python3 code_hunter.py oracle bundle targets/hackerone/shopify

# 4. Verify the bundle (manual - needs path)
python3 code_hunter.py oracle verify-download targets/hackerone/shopify/reports/product_*.zip --json

# 5. View consolidated report
python3 code_hunter.py report --output my_hunt_report.json
```

## Unwired Flags (documented, not yet connected to pipeline)

These flags exist on individual commands but aren't auto-injected by `pipeline --run`:

- `--cdp-port` — CDP port for Chrome debugging (default 9227)
- `--controlled` — controlled/low-rate recon (default on)
- `--testnet` — testnet safe-mode for hunts
- `--code` — code lens flag
- `--voice` — Alex voice mode
- `--no-resume` — ignore prior queue state
- `--skip-download` — don't ensure workspaces before hunting

To use these, run the individual `oracle` subcommands manually instead of `pipeline --run`.
