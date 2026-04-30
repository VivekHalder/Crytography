"""
ECC Toolkit — Web Backend
=========================

Thin FastAPI wrapper around KeyGeneration.py / Encrypt.py / Decrypt.py.

Each request spawns `sage <script>.py ...` in an isolated working directory,
captures the JSON files written to disk, and returns them.

Run from the repository root (where KeyGeneration.py etc. live):

    pip install -r requirements.txt
    uvicorn server:app --reload --port 8000

The frontend is served at /, the API lives under /api.
"""

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Paths and configuration
# ---------------------------------------------------------------------------

# All scripts live in the same directory as this file.
# Override with ECC_REPO_ROOT if you keep them elsewhere.
REPO_ROOT = Path(os.environ.get("ECC_REPO_ROOT", Path(__file__).resolve().parent))
KEYGEN_SCRIPT = REPO_ROOT / "KeyGeneration.py"
ENCRYPT_SCRIPT = REPO_ROOT / "Encrypt.py"
DECRYPT_SCRIPT = REPO_ROOT / "Decrypt.py"

SAGE_BIN = os.environ.get("SAGE_BIN", "sage")
SCRIPT_TIMEOUT_SEC = int(os.environ.get("ECC_TIMEOUT", "300"))

FRONTEND_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class KeyGenRequest(BaseModel):
    mode: int = Field(..., ge=0, le=3)
    # Mode 0
    base_field: Optional[str] = None
    degree: Optional[int] = None
    a1: Optional[str] = None
    a2: Optional[str] = None
    a3: Optional[str] = None
    a4: Optional[str] = None
    a6: Optional[str] = None
    # Mode 2
    curve_name: Optional[str] = None
    # Mode 3
    bits: Optional[int] = None


class EncryptRequest(BaseModel):
    mode: int = Field(..., ge=1, le=2)  # 1 = ASCII, 2 = points
    public_key_json: dict
    message: str


class DecryptRequest(BaseModel):
    mode: int = Field(..., ge=1, le=2)
    private_key_json: dict
    public_key_json: dict
    ciphertext_json: dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_sage(args: list[str], cwd: Path) -> tuple[str, str, int]:
    """Execute `sage <args>` in cwd, return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            [SAGE_BIN, *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=SCRIPT_TIMEOUT_SEC,
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"`{SAGE_BIN}` not found on PATH. "
                "Install SageMath or set the SAGE_BIN environment variable."
            ),
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail=f"Sage script exceeded the {SCRIPT_TIMEOUT_SEC}s timeout. "
                   "Try smaller parameters (lower bits, smaller field).",
        )
    return proc.stdout, proc.stderr, proc.returncode


def _ensure_scripts_exist():
    missing = [p.name for p in (KEYGEN_SCRIPT, ENCRYPT_SCRIPT, DECRYPT_SCRIPT) if not p.exists()]
    if missing:
        raise HTTPException(
            status_code=500,
            detail=f"Cannot find Sage scripts at {REPO_ROOT}: missing {missing}. "
                   "Set ECC_REPO_ROOT to the directory containing them.",
        )


def _new_workdir() -> Path:
    """Per-request scratch directory (cleaned up on success or failure)."""
    d = Path(tempfile.gettempdir()) / f"ecc-{uuid.uuid4().hex[:12]}"
    d.mkdir(parents=True, exist_ok=False)
    # Copy the scripts in so Sage can find them as if it were the repo root.
    for src in (KEYGEN_SCRIPT, ENCRYPT_SCRIPT, DECRYPT_SCRIPT):
        shutil.copy2(src, d / src.name)
    return d


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="ECC Toolkit Web", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    sage_ok = shutil.which(SAGE_BIN) is not None
    return {
        "status": "ok",
        "sage_available": sage_ok,
        "sage_bin": SAGE_BIN,
        "repo_root": str(REPO_ROOT),
        "scripts_found": {
            "KeyGeneration.py": KEYGEN_SCRIPT.exists(),
            "Encrypt.py": ENCRYPT_SCRIPT.exists(),
            "Decrypt.py": DECRYPT_SCRIPT.exists(),
        },
    }


# ----- Key generation ------------------------------------------------------

@app.post("/api/keygen")
def keygen(req: KeyGenRequest):
    _ensure_scripts_exist()
    work = _new_workdir()
    try:
        # Build argv for the script based on mode (mirrors the CLI exactly)
        argv: list[str] = ["KeyGeneration.py", str(req.mode)]

        if req.mode == 0:
            for name, value in (
                ("base_field", req.base_field),
                ("degree", req.degree),
                ("a1", req.a1),
                ("a2", req.a2),
                ("a3", req.a3),
                ("a4", req.a4),
                ("a6", req.a6),
            ):
                if value is None or value == "":
                    raise HTTPException(400, f"Mode 0 requires {name}")
            argv += [
                str(req.base_field), str(req.degree),
                str(req.a1), str(req.a2), str(req.a3), str(req.a4), str(req.a6),
            ]
        elif req.mode == 1:
            if req.base_field is None or req.degree is None:
                raise HTTPException(400, "Mode 1 requires base_field and degree")
            argv += [str(req.base_field), str(req.degree)]
        elif req.mode == 2:
            if not req.curve_name:
                raise HTTPException(400, "Mode 2 requires curve_name")
            argv += [req.curve_name]
        elif req.mode == 3:
            if req.bits is None or req.degree is None:
                raise HTTPException(400, "Mode 3 requires bits and degree")
            argv += [str(req.bits), str(req.degree)]

        argv.append("--debug")  # capture human-readable summary in stdout

        stdout, stderr, rc = _run_sage(argv, cwd=work)
        if rc != 0:
            raise HTTPException(400, f"KeyGeneration.py failed:\n{stderr or stdout}")

        pub_path = work / "ecc_public_key.txt"
        priv_path = work / "ecc_private_key.txt"
        if not pub_path.exists() or not priv_path.exists():
            raise HTTPException(500, f"Key files not produced. Output:\n{stdout}\n{stderr}")

        return {
            "public_key": json.loads(pub_path.read_text()),
            "private_key": json.loads(priv_path.read_text()),
            "summary": stdout.strip(),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ----- Encryption ----------------------------------------------------------

@app.post("/api/encrypt")
def encrypt(req: EncryptRequest):
    _ensure_scripts_exist()
    work = _new_workdir()
    try:
        pub_path = work / "ecc_public_key.txt"
        msg_path = work / "message.txt"
        pub_path.write_text(json.dumps(req.public_key_json, indent=2))
        msg_path.write_text(req.message)

        argv = [
            "Encrypt.py", str(req.mode),
            "ecc_public_key.txt", "message.txt",
            "--debug",
        ]
        stdout, stderr, rc = _run_sage(argv, cwd=work)
        if rc != 0:
            raise HTTPException(400, f"Encrypt.py failed:\n{stderr or stdout}")

        cipher_path = work / "ecc_ciphertext.txt"
        if not cipher_path.exists():
            raise HTTPException(500, f"Ciphertext not produced. Output:\n{stdout}\n{stderr}")

        return {
            "ciphertext": json.loads(cipher_path.read_text()),
            "summary": stdout.strip(),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ----- Decryption ----------------------------------------------------------

@app.post("/api/decrypt")
def decrypt(req: DecryptRequest):
    _ensure_scripts_exist()
    work = _new_workdir()
    try:
        priv_path = work / "ecc_private_key.txt"
        pub_path = work / "ecc_public_key.txt"
        cipher_path = work / "ecc_ciphertext.txt"
        priv_path.write_text(json.dumps(req.private_key_json, indent=2))
        pub_path.write_text(json.dumps(req.public_key_json, indent=2))
        cipher_path.write_text(json.dumps(req.ciphertext_json, indent=2))

        argv = [
            "Decrypt.py", str(req.mode),
            "ecc_private_key.txt", "ecc_public_key.txt", "ecc_ciphertext.txt",
        ]
        stdout, stderr, rc = _run_sage(argv, cwd=work)
        if rc != 0:
            raise HTTPException(400, f"Decrypt.py failed:\n{stderr or stdout}")

        # Strip the trailing "Time Taken: …" line so only the plaintext is shown.
        lines = stdout.strip().splitlines()
        output_lines = [l for l in lines if not l.startswith("Time Taken")]
        return {
            "output": "\n".join(output_lines).strip(),
            "timing": next((l for l in lines if l.startswith("Time Taken")), ""),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ----- Static frontend -----------------------------------------------------
# Serve only the three known frontend files to avoid exposing Python source.

_STATIC = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/styles.css": "styles.css",
}

@app.get("/{full_path:path}", include_in_schema=False)
def static(full_path: str):
    route = "/" + full_path if full_path else "/"
    filename = _STATIC.get(route)
    if filename is None:
        return Response(status_code=404)
    path = FRONTEND_DIR / filename
    if not path.exists():
        return JSONResponse({"message": f"Frontend file {filename} not found."}, status_code=404)
    return FileResponse(str(path))
