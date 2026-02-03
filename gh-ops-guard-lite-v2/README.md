# GH Ops Guard Lite (no hidden folders)

This Lite package intentionally **does NOT include** a `.github/` folder, because dot-folders often get lost when people manually copy files or upload via the GitHub web UI.

Instead, you will **create the workflow file yourself** using the steps below.

## 1) Local quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python guard.py --check
```

## 2) GitHub Actions setup (copy-paste)

### Create the workflow file

In your repo on GitHub:
1. Go to **Actions** (or just go to the repo root).
2. Click **Add file** → **Create new file**
3. In the filename box, type exactly:

```
.github/workflows/ops-guard.yml
```

GitHub will create the folders automatically.

### Paste this workflow YAML

Paste the following into the file and commit:

```yaml
name: ops-guard-lite

on:
  workflow_dispatch:
  pull_request:
  push:
    branches: [ "main" ]

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run GH Ops Guard Lite
        env:
          # Pass required runtime secrets as env vars (GitHub masks them).
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
        run: |
          python guard.py --check

```

### Add required secrets (optional but recommended)

If your `ops_guard.yml` has `required_env` like `OPENAI_API_KEY`, set GitHub secrets:

Repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

Then the workflow passes them into the job via `env:`.

## What it checks

- Required runtime env vars (you define them in `ops_guard.yml`)
- Secret leakage scan (common key patterns + private key blocks)
- Workflow waste scan (detects `sleep N` above threshold)
- Action pinning (warn only in Lite)

## Config

Edit `ops_guard.yml`.

## Exit codes

- `0`: OK
- `2`: Findings (fails the job)
- `1`: Internal error

## License

MIT
