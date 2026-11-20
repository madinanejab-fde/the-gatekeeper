import sys
import json
import uuid
from pathlib import Path
import duckdb
from shield import wrap_untrusted_payload

# Base paths matching your repository-agnostic structure
BASE_DIR = Path(__file__).resolve().parent
SANITIZED_DIR = BASE_DIR / "sanitized_output"
DB_PATH = BASE_DIR / "gatekeeper_audit.duckdb"


def log_mcp_retrieval(request_id: str, client_id: str, action: str, target: str):
    """Logs every MCP tool invocation with request_id and client_id to DuckDB for immutable audit traceability."""
    try:
        conn = duckdb.connect(str(DB_PATH))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_access_logs (
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                request_id VARCHAR,
                mcp_client_id VARCHAR,
                action_performed VARCHAR,
                target_resource VARCHAR
            )
        """)
        conn.execute(
            "INSERT INTO mcp_access_logs (request_id, mcp_client_id, action_performed, target_resource) VALUES (?, ?, ?, ?)",
            [request_id, client_id, action, target]
        )
        conn.close()
    except Exception as e:
        print(f"[MCP AUDIT WARNING] Failed to write access log: {e}", file=sys.stderr)


# --- SOURCE-AGNOSTIC, READ-ONLY MCP TOOLS ---

def fetch_sanitized_document(args: dict) -> str:
    """
    MCP Tool: fetch_sanitized_document
    Fetches a sanitized, PII-stripped document from the secure Gold layer,
    applies structural spotlighting, and logs the request trace event.
    """
    document_path = args.get("document_path")
    mcp_client_id = args.get("mcp_client_id", "default_client")
    request_id = args.get("request_id", str(uuid.uuid4())[:8].upper())
    
    if not document_path:
        raise ValueError("Fail-Closed: 'document_path' argument is required.")

    target_file = (SANITIZED_DIR / document_path).resolve()
    
    # Security boundary check: prevent path traversal
    if not str(target_file).startswith(str(SANITIZED_DIR.resolve())):
        raise ValueError("Fail-Closed: Access denied. Path traversal detected outside sanitized output.")
    
    if not target_file.exists():
        raise FileNotFoundError(f"Fail-Closed: Requested document '{document_path}' not found in sanitized repository.")
    
    with open(target_file, "r", encoding="utf-8") as f:
        scrubbed_content = f.read()
    
    # Wrap in prompt-injection spotlighting boundaries
    secured_payload = wrap_untrusted_payload(scrubbed_content, document_path)
    
    # Log trace event with request_id and client_id
    log_mcp_retrieval(request_id, mcp_client_id, "FETCH_DOCUMENT", document_path)
    
    return secured_payload


def query_repository_summary(args: dict) -> str:
    """
    MCP Tool: query_repository_summary
    Queries the DuckDB operational audit ledger for high-level ingestion metrics
    and file processing summaries across the repository.
    """
    mcp_client_id = args.get("mcp_client_id", "default_client")
    request_id = args.get("request_id", str(uuid.uuid4())[:8].upper())
    
    if not DB_PATH.exists():
        return json.dumps({"status": "error", "message": "Audit ledger not initialized."})
    
    conn = duckdb.connect(str(DB_PATH), read_only=True)
    logs = conn.execute("SELECT original_filename, functional_zone, token_savings_percent, status FROM audit_logs").fetchall()
    conn.close()
    
    summary = [
        {
            "filename": row[0],
            "functional_zone": row[1],
            "token_savings_percent": float(row[2]) if row[2] else 0.0,
            "status": row[3]
        }
        for row in logs
    ]
    
    log_mcp_retrieval(request_id, mcp_client_id, "QUERY_REPOSITORY_SUMMARY", "audit_logs")
    
    return json.dumps({"repository_status": "SECURE", "request_id": request_id, "records": summary}, indent=2)


TOOLS = {
    "fetch_sanitized_document": fetch_sanitized_document,
    "query_repository_summary": query_repository_summary
}


def main():
    # Native JSON-RPC over Stdio Loop for Model Context Protocol
    for line in sys.stdin:
        try:
            message = json.loads(line)
            req_id = message.get("id")
            method = message.get("method")
            params = message.get("params", {})
            
            if method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "fetch_sanitized_document",
                                "description": "Fetch sanitized document from Gold layer with prompt injection spotlighting.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "document_path": {"type": "string"},
                                        "mcp_client_id": {"type": "string"},
                                        "request_id": {"type": "string"}
                                    },
                                    "required": ["document_path", "mcp_client_id"]
                                }
                            },
                            {
                                "name": "query_repository_summary",
                                "description": "Query DuckDB operational audit ledger for ingestion metrics.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "mcp_client_id": {"type": "string"},
                                        "request_id": {"type": "string"}
                                    },
                                    "required": ["mcp_client_id"]
                                }
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                if tool_name in TOOLS:
                    result_text = TOOLS[tool_name](tool_args)
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": result_text}]
                        }
                    }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Tool '{tool_name}' not found."}
                    }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method '{method}' not found."}
                }
            
            print(json.dumps(response))
            sys.stdout.flush()
        
        except Exception as e:
            err_response = {
                "jsonrpc": "2.0",
                "id": message.get("id") if 'message' in locals() else None,
                "error": {"code": -32603, "message": str(e)}
            }
            print(json.dumps(err_response))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
    