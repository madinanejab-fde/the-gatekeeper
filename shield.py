import re


def scrub_prompt_injections(text: str):
    """Strips invisible characters and neutralizes common prompt-injection phrases."""
    cleaned = re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff]", "", text)
    patterns = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"(?i)system\s*:\s*",
        r"(?i)<\s*/?\s*system\s*>",
    ]
    hits = 0
    for pat in patterns:
        cleaned, count = re.subn(pat, "[REDACTED_DIRECTIVE]", cleaned)
        hits += count
    return cleaned, hits


def wrap_untrusted_payload(content: str, source_label: str) -> str:
    """Wraps sanitized file content inside clear boundary tags for downstream AI readers."""
    safe_content, _ = scrub_prompt_injections(content)
    return (
        f'<untrusted_repository_data source="{source_label}">\n'
        f"{safe_content}\n"
        f"</untrusted_repository_data>"
    )