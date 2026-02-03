# GH Ops Guard Lite

A tiny, repo-friendly safety gate you can run **locally** or in **GitHub Actions** to prevent common (and expensive) mistakes:
- missing env/secrets at runtime
- accidentally committing API keys
- workflow "sleep" steps that waste Actions minutes
- unpinned actions (optional warning)

This is the **Lite** edition: one command, one report, fail-fast if issues are found.

## Quick start (local)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python guard.py --init
python guard.py --check
```

## Quick start (GitHub Actions)

1) Copy `.github/workflows/ops-guard.yml` into your repo  
2) (Optional) Set required env vars in `ops_guard.yml` and pass them as `env:` in your workflow step  
3) Push

## What it checks

- **Required runtime env vars** (you define them)
- **Secret leakage scan** (common key patterns, private keys, token-like strings)
- **Workflow waste scan** (detects `sleep 900` etc. above a threshold)
- **Action pinning (warn)** (flags `uses: owner/action@v3` instead of a SHA)

## Config

Edit `ops_guard.yml`.

## Exit codes

- `0`: OK
- `2`: Findings (fails the job)
- `1`: Internal error

## Notes

- In GitHub Actions, secrets are not readable directly. Pass required secrets into the step as env vars (still masked by GitHub).
- The secret scan is conservative: it may produce false positives. Tune patterns in `ops_guard.yml`.

## License

MIT
