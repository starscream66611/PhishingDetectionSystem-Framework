# Run with: .\run.ps1
# (Assumes you already activated venv and installed requirements)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
