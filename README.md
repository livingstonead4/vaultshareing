# VaultShare

A starter web application for document upload and integrity verification.

## Run locally

Requires Python 3.11+.

### Windows
```powershell
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### macOS / Linux
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000.

## Current functionality
- Create an account and sign in
- Upload documents
- List your uploaded documents
- Verify file integrity using SHA-256
- Download your own uploaded documents

## Important limitations
This is a learning/demo starter, not a production secure document-sharing system. The share endpoint records an invitation but does not grant recipient access. Files are stored locally without encryption at rest. There is no MFA, email verification, malware scanning, robust audit trail, or production-grade access-control review. Do not use it for confidential or sensitive documents. Before deployment, configure a strong SECRET_KEY and persistent database/file storage, add backups, and arrange a security review.
