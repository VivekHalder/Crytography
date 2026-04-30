# =============================================================================
# Dockerfile — ECC Frontend Application
# =============================================================================
# Description:
#     Builds a containerised environment for the ECC (Elliptic Curve
#     Cryptography) web application. Provides key generation, encryption,
#     and decryption via a FastAPI/Uvicorn backend served on port 8000.
#
# Base Image:
#     sagemath/sagemath:latest — includes SageMath, Python 3, and a full
#     suite of mathematical libraries required for ECC operations.
#
# Usage:
#     Build : docker build -t ecc-fe .
#     Run   : docker run -p 8000:8000 ecc-fe
#
# Exposed Ports:
#     8000 — Uvicorn ASGI server (HTTP)
#
# Entry Point:
#     python3 -m uvicorn server:app --host 0.0.0.0 --port 8000
# =============================================================================

FROM sagemath/sagemath:latest

# Switch to root so we have permission to install packages.
# The default SageMath image runs as the unprivileged 'sage' user.
USER root

# Copy requirements first (before application code) so Docker can cache
# this layer. If requirements.txt is unchanged, pip install is skipped
# on subsequent rebuilds, speeding up the build process.
COPY requirements.txt .

# Install Python dependencies into the SageMath virtual environment.
#
# Why `sage -pip` and not `pip3`:
#     The SageMath image ships its own Python venv
#     (/home/sage/sage/local/var/lib/sage/venv-pythonX.Y/) and places it
#     first on PATH. When the container starts, `python3` resolves to that
#     venv — not the system Python. Using the system `pip3` would install
#     packages into the wrong interpreter, causing "No module named uvicorn"
#     at runtime. `sage -pip` targets the same Python that `python3` uses,
#     so the packages are always found.
#
# Flags:
#     --no-cache-dir -- prevents pip from writing download caches to the image;
#                       caches are never reused inside a container so omitting
#                       them keeps the image size smaller.
RUN sage -pip install --no-cache-dir -r requirements.txt

# Set the working directory for all subsequent instructions.
# The directory is created automatically if it does not exist.
WORKDIR /app

# Copy application source files into the container.
#
# Files:
#     KeyGeneration.py -- ECC key-pair generation logic
#     Encrypt.py       -- ECC encryption implementation
#     Decrypt.py       -- ECC decryption implementation
#     server.py        -- FastAPI application and API route definitions
#     index.html       -- Frontend entry point
#     app.js           -- Frontend JavaScript logic
#     styles.css       -- Frontend stylesheet
COPY KeyGeneration.py Encrypt.py Decrypt.py \
     server.py index.html app.js styles.css ./

# Inform Docker (and tooling) that the container listens on port 8000.
# This does NOT publish the port; use -p 8000:8000 at runtime to do so.
EXPOSE 8000

# Default command: start the Uvicorn ASGI server.
#
# Args:
#     server:app    -- load the 'app' object from server.py
#     --host 0.0.0.0 -- bind to all interfaces (required for external access)
#     --port 8000    -- match the EXPOSE declaration above
CMD ["python3", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
