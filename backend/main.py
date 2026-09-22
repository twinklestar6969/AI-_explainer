import sys
from pathlib import Path

# Allow backend to access the existing scanner
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scanner"))

from fastapi import FastAPI 
from fastapi.middleware.cors import CORSMiddleware

from scanner.main import run_scan


app = FastAPI(title="AWS Security Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "AWS Security Scanner API"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan_aws():
    return run_scan()