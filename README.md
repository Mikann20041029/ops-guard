# GH Ops Guard Lite (ready-to-run)

This package is structured so you can **unzip and commit to the repo root** and it should work immediately.

## Folder layout (must be repo root)

After you copy files into your repository root, you should have:

- guard.py
- ops_guard.yml
- requirements.txt
- .github/workflows/ops-guard.yml

If you put this folder inside another folder, GitHub Actions will NOT detect the workflow.

## Local quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python guard.py --check
```

## GitHub Actions quick start

1) Copy the contents of this zip into your repo root (so `.github/` is at the repo root)
2) Add secrets (optional, only if you keep `required_env`):
   Repo → Settings → Secrets and variables → Actions → New repository secret
3) Go to Actions → `ops-guard-lite` → Run workflow

### If you don't want secrets
Edit `ops_guard.yml` and set:
```yaml
required_env: []
```

## What it checks

- Required env vars (you define them in `ops_guard.yml`)
- Secret leakage scan (common key patterns + private key blocks)
- Workflow waste scan (detects `sleep N` above threshold)
- Action pinning (warn only in Lite)

## Exit codes

- 0: OK
- 2: Findings (job fails)
- 1: Internal error

## License

MIT
