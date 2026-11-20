import os
import sys
import json
import uuid
from typing import Optional
from pathlib import Path
import duckdb
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from shield import wrap_untrusted_payload

OUTPUT_DIR = BASE_DIR / "sanitized_output"
DB_PATH = str(BASE_DIR / "gatekeeper_audit.duckdb")


def _ensure_mcp_log_table():
    """Creates mcp_access_logs if not yet present."""
    conn = duckdb.connect(DB_PATH)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_access_logs (
                access_id VARCHAR,
                timestamp TIMESTAMP,
                tool_name VARCHAR,
                target_resource VARCHAR,
                status VARCHAR,
                notes VARCHAR
            )
        """)
    finally:
        conn.close()


def _log_mcp_access(tool_name: str, target_resource: str, status: str, notes: str = ""):
    try:
        _ensure_mcp_log_table()
        conn = duckdb.connect(DB_PATH)
        try:
            conn.execute(
                "INSERT INTO mcp_access_logs VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?)",
                [str(uuid.uuid4())[:8].upper(), tool_name, target_resource, status, notes[:250]],
            )
        finally:
            conn.close()
    except Exception:
        pass


def _resolve_sanitized_file(relative_path: str) -> Path:
    """Prevents path traversal outside sanitized_output."""
    clean_rel = Path(relative_path.lstrip("/\\"))
    resolved = (OUTPUT_DIR / clean_rel).resolve()
    root_resolved = OUTPUT_DIR.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError("Access denied: path outside sanitized_output.")
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(f"Sanitized file not found: {relative_path}")
    return resolved


def tool_list_sanitized_files() -> str:
    if not OUTPUT_DIR.exists():
        _log_mcp_access("list_sanitized_files", "sanitized_output", "EMPTY")
        return json.dumps({"files": [], "note": "sanitized_output does not exist yet."})

    files = []
    for p in sorted(OUTPUT_DIR.rglob("*")):
        if p.is_file() and "quarantine" not in p.parts and not p.name.startswith("."):
            files.append({
                "relative_path": str(p.relative_to(OUTPUT_DIR)),
                "size_bytes": p.stat().st_size,
            })

    _log_mcp_access("list_sanitized_files", "sanitized_output", "SUCCESS", f"count={len(files)}")
    return json.dumps({"count": len(files), "files": files}, indent=2)


def tool_read_sanitized_file(relative_path: str) -> str:
    try:
        target = _resolve_sanitized_file(relative_path)
        if "quarantine" in target.parts:
            _log_mcp_access("read_sanitized_file", relative_path, "BLOCKED", "Quarantined file blocked")
            return json.dumps({"error": "Quarantined files cannot be read through MCP."})

        raw_content = target.read_text(encoding="utf-8", errors="replace")
        wrapped = wrap_untrusted_payload(raw_content, str(target.relative_to(OUTPUT_DIR)))
        _log_mcp_access("read_sanitized_file", relative_path, "SUCCESS", f"bytes={len(raw_content)}")
        return wrapped
    except Exception as exc:
        _log_mcp_access("read_sanitized_file", relative_path, "ERROR", str(exc))
        return json.dumps({"error": str(exc)})


def tool_get_audit_summary(limit: int = 20) -> str:
    safe_limit = max(1, min(int(limit), 100))
    if not os.path.exists(DB_PATH):
        _log_mcp_access("get_audit_summary", "audit_logs", "EMPTY", "DB missing")
        return json.dumps({"error": "gatekeeper_audit.duckdb not found."})

    conn = duckdb.connect(DB_PATH, read_only=True)
    try:
        rows = conn.execute(
            """
            SELECT run_id, timestamp, original_filename, pseudonymized_filename,
                   functional_zone, entities_redacted_count, tokens_before, tokens_after,
                   token_savings_percent, status
            FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            [safe_limit],
        ).fetchall()
        columns = [
            "run_id", "timestamp", "original_filename", "pseudonymized_filename",
            "functional_zone", "entities_redacted_count", "tokens_before", "tokens_after",
            "token_savings_percent", "status",
        ]
        records = [dict(zip(columns, [str(v) if not isinstance(v, (int, float, type(None))) else v for v in r])) for r in rows]
        _log_mcp_access("get_audit_summary", "audit_logs", "SUCCESS", f"rows={len(records)}")
        return json.dumps({"count": len(records), "records": records}, indent=2)
    except Exception as exc:
        _log_mcp_access("get_audit_summary", "audit_logs", "ERROR", str(exc))
        return json.dumps({"error": str(exc)})
    finally:
        conn.close()


TOOLS = [
    {
        "name": "list_sanitized_files",
        "description": "List all sanitized, POPIA/GDPR-scrubbed files available in sanitized_output (excludes quarantine).",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "read_sanitized_file",
        "description": "Read a sanitized file by relative path inside sanitized_output, wrapped in untrusted-data boundary tags.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "relative_path": {
                    "type": "string",
                    "description": "Relative path inside sanitized_output, e.g. 'financials/reports/sample_123456.txt'.",
                }
            },
            "required": ["relative_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_audit_summary",
        "description": "Retrieve recent airlock processing and quarantine audit records from DuckDB (read-only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of audit rows to return (1-100, default 20).",
                    "default": 20,
                }
            },
            "additionalProperties": False,
        },
    },
]


def handle_rpc_message(msg: dict) -> Optional[dict]:
    msg_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "gatekeeper-vdr-mcp",
                    "version": "1.0.0",
                },
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}

        if tool_name == "list_sanitized_files":
            text_out = tool_list_sanitized_files()
        elif tool_name == "read_sanitized_file":
            text_out = tool_read_sanitized_file(args.get("relative_path", ""))
        elif tool_name == "get_audit_summary":
            text_out = tool_get_audit_summary(args.get("limit", 20))
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": text_out}],
                "isError": False,
            },
        }

    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main():
    _ensure_mcp_log_table()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
            continue

        resp = handle_rpc_message(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()