import os
import re
from pathlib import Path
import duckdb
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="The Gatekeeper: Sovereign M&A VDR Airlock",
    description="POPIA-compliant secure middleware interceptor and functional Gold Zone query engine.",
    version="1.0.0"
)

DB_PATH = "gatekeeper_audit.duckdb"
GOLD_ZONE_DIR = Path("sanitized_output")


class QueryRequest(BaseModel):
    executive_query: str


def intercept_and_translate_query(natural_query: str) -> tuple[str, list[str]]:
    """
    Middleware Interceptor: Read-only lookup against DuckDB audit/mapping ledger.
    """
    if not os.path.exists(DB_PATH):
        return natural_query, []

    conn = duckdb.connect(DB_PATH, read_only=True)
    try:
        cols = [row[1] for row in conn.execute("PRAGMA table_info('entity_mappings')").fetchall()]
        if "raw_entity_value" in cols:
            mappings = conn.execute("SELECT raw_entity_value, pseudonym_alias FROM entity_mappings").fetchall()
        else:
            mappings = []
    except Exception:
        mappings = []
    finally:
        conn.close()

    translated_query = natural_query
    matched_aliases = []

    for raw_val, alias in mappings:
        if raw_val and raw_val.lower() in natural_query.lower():
            translated_query = re.sub(re.escape(raw_val), alias, translated_query, flags=re.IGNORECASE)
            matched_aliases.append(alias)

    return translated_query, matched_aliases