# FRAUD DESK — Single-App End-to-End

This version intentionally has **one Python application file**. There are no separate `backend/` or `frontend/` directories. The FastAPI API, SQLite persistence, IOC extraction, Hindsight Cloud integration, Groq analysis, artifacts, dispatch audit, and complete UI are all contained in `app.py`.

## Windows

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000

## Health check

Open http://127.0.0.1:8000/api/health before testing a case. `hindsight_available` should be `true`. If it is false, the response contains `hindsight_error`.

## End-to-end learning flow

1. Analyze an inbound fraud message with Hindsight enabled.
2. Review the Before/After score and recalled memories.
3. Confirm or reject the case as an analyst.
4. The verdict is retained into the `fraud-desk` Hindsight bank.
5. Analyze a related future case and verify historical context is recalled.
6. Generate an operational artifact and create an audited dispatch package.

## Security

The included `.env` contains the credentials supplied during setup. Rotate those credentials after testing because they were exposed in the chat/session. Do not commit `.env` to Git.

The app does not falsely claim a government portal submission. External submission requires an explicitly configured webhook and remains subject to human authorization.
