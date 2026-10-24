# TrustVault — Secure Document Sharing with an Audit Trail

A beginner-friendly Flask + SQLite web app inspired by the SnovaSys hiring challenge brief. It supports accounts, encrypted file storage, explicit sharing permissions, access revocation, and audit events.

## Features

- Register and sign in with password hashing.
- Upload supported documents up to 15 MB.
- Encrypt file bytes at rest using Fernet authenticated encryption.
- Share documents with another registered user as `read` or `download`.
- Revoke shared access.
- Record sign-in, upload, metadata view, read, download, share, and revoke events.
- Store document SHA-256 hashes in metadata.
- Simple responsive UI and SQLite database; no external database service required.

## Requirements

- Python 3.10 or newer
- Windows, macOS, or Linux

## Run on Windows (PowerShell)

Open PowerShell in the extracted `TrustVault` folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, use the virtual environment's Python directly:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000 in your browser. Register two accounts to test sharing between users.

## Run on macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

## Demo flow

1. Register `alice` and `bob` with passwords of at least 8 characters.
2. Sign in as Alice and upload a `.txt` file.
3. Open the document details and share it with Bob using `read` or `download`.
4. Sign out and sign in as Bob.
5. Open the shared document. Bob can only access the document if Alice granted access.
6. Sign back in as Alice and revoke access.
7. Open **Audit trail** to inspect recorded actions.

## Supported file types

`.pdf`, `.txt`, `.doc`, `.docx`, `.png`, `.jpg`, `.jpeg`, `.xlsx`, `.csv`

## Security notes — read before public deployment

This is a hiring-challenge/demo MVP, not a production-certified secure document service.

- Replace `TRUSTVAULT_SECRET` with a strong random secret and keep it outside source control.
- Back up and protect `data/fernet.key`. Losing it makes encrypted files unreadable. Anyone who obtains it can decrypt stored files.
- The local encryption key is created automatically for convenience. For deployment, set `TRUSTVAULT_ENCRYPTION_KEY` from a secure secret manager and do not commit it.
- Use HTTPS, CSRF protection, rate limiting, secure cookie settings, and a production WSGI server before exposing the app to the internet.
- Audit logs are application-level records, not tamper-proof external logs. A privileged server/database operator could alter them. For stronger evidence, forward logs to append-only or independently controlled storage.
- The app logs the IP address observed by Flask. Configure trusted proxies carefully; do not blindly trust client-supplied forwarding headers in production.
- Read permission means the recipient may view `.txt` files in the browser; other file types are delivered as downloads because browsers cannot safely render every format consistently.
- Revocation prevents future access through this app. It cannot erase a file that a recipient already downloaded or copied.
- Do not upload real confidential or personal documents to a demo deployment.

## Project structure

```text
TrustVault/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── document.html
│   ├── read_text.html
│   ├── audit.html
│   └── error.html
├── static/
│   └── style.css
└── data/
    └── encrypted_files/
```

## GitHub

1. Extract the ZIP.
2. Open the extracted folder in VS Code.
3. Create a new GitHub repository.
4. Do **not** upload `.env`, `data/fernet.key`, the SQLite database, or real uploaded files.
5. Upload the project files and commit.
6. In the GitHub repository description, mention that this is a local demo MVP and include the security limitations above.

## Troubleshooting

- `ModuleNotFoundError: No module named 'flask'`: activate the environment and run `python -m pip install -r requirements.txt`.
- Port 5000 is busy: stop the other process or change the last line to `app.run(port=5001, ...)`.
- Files cannot be decrypted after moving the project: make sure the original private `data/fernet.key` is present, or set the same `TRUSTVAULT_ENCRYPTION_KEY`.
- `No module named cryptography`: run `python -m pip install cryptography`.
