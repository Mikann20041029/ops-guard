# GH Ops Guard Lite

## What this does
Runs quick safety checks for your repo (missing env vars, secret leakage, workflow waste, and action pinning warnings).  
Fails CI when critical findings are detected.

## Local run
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python guard.py --check
```

## GitHub Actions setup

File name (create this file on GitHub):

.github/workflows/ops-guard.yml

How to add (GitHub UI):
1. Open your repository on GitHub
2. Click Add file → Create new file
3. In the filename box, paste exactly:

.github/workflows/ops-guard.yml

4. Paste the YAML below into the editor
5. Click Commit changes (commit to your default branch)

Workflow YAML (copy-paste):

```yaml
name: ops-guard-lite

on:
  workflow_dispatch:
  pull_request:
  push:
    branches: ["main"]

jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          if [ -f requirements.txt ]; then
            pip install -r requirements.txt
          else
            echo "requirements.txt not found; skipping"
          fi

      - name: Run
        env:
          # Optional: only if your tool needs secrets
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
        run: |
          python guard.py --check

```

Add secrets (optional):

Repo → Settings → Secrets and variables → Actions → New repository secret

#~ If you keep `required_env` in ops_guard.yml, set the corresponding Secrets in GitHub.

## How to verify
1. Open the **Actions** tab
2. Click **ops-guard-lite**
3. Click **Run workflow** → **Run workflow**

## Troubleshooting (no “Run workflow” button)
- The workflow file is not on the default branch
- workflow_dispatch is missing or YAML indentation is broken
- The file path is not exactly .github/workflows/ops-guard.yml
