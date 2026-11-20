import os
from dotenv import load_dotenv

load_dotenv()

import hashlib
import hmac
import secrets
import re
import json
import uuid
from pathlib import Path
import duckdb
import shutil
from shield import scrub_prompt_injections

# Optional BPE tokenizer for exact LLM token economy metrics
try:
    import tiktoken
    _bpe_encoder = tiktoken.get_encoding("cl100k_base")
except ImportError:
    _bpe_encoder = None

# Document & OCR parsing libraries
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None

try:
    import openpyxl
except ImportError:
    openpyxl = None

try:
    import pytesseract
    from PIL import Image
    if os.path.exists('/opt/homebrew/bin/tesseract'):
        pytesseract.pytesseract.tesseract_cmd = '/opt/homebrew/bin/tesseract'
    elif os.path.exists('/usr/local/bin/tesseract'):
        pytesseract.pytesseract.tesseract_cmd = '/usr/local/bin/tesseract'
except ImportError:
    pytesseract = None
    Image = None

# Microsoft Presidio PII Engine & Checksum-Resilient Format Recognizers
try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    
    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    # 1. SA ID Shape & Luhn Check-Digit Validator
    def check_sa_luhn_digit(val: str) -> bool:
        digits = [int(c) for c in val if c.isdigit()]
        if len(digits) != 13:
            return False
        checksum = 0
        for i, digit in enumerate(digits[::-1]):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += (doubled - 9) if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    class SAIdentifierFormatRecognizer(PatternRecognizer):
        def validate_result(self, pattern_text: str) -> bool:
            _ = check_sa_luhn_digit(pattern_text)
            return True

    sa_id_pattern = Pattern(
        name="sa_id_shape_pattern",
        regex=r'\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[1-2]\d|3[0-1])\d{7}\b',
        score=0.95
    )
    analyzer.registry.add_recognizer(
        SAIdentifierFormatRecognizer(
            supported_entity="ZA_ID_NUMBER",
            patterns=[sa_id_pattern],
            context=["id", "identity", "id number", "south african id", "citizen"]
        )
    )

    # 2. SARS Tax Shape & Mod-10 Check-Digit Validator
    def check_sars_mod10_digit(val: str) -> bool:
        digits = [int(c) for c in val if c.isdigit()]
        if len(digits) != 10:
            return False
        total = 0
        for i, digit in enumerate(digits[:9]):
            if i % 2 == 0:
                doubled = digit * 2
                total += (doubled // 10) + (doubled % 10) if doubled > 9 else doubled
            else:
                total += digit
        last_digit_total = total % 10
        check_digit = 0 if last_digit_total == 0 else 10 - last_digit_total
        return check_digit == digits[9]

    class SARSIdentifierFormatRecognizer(PatternRecognizer):
        def validate_result(self, pattern_text: str) -> bool:
            _ = check_sars_mod10_digit(pattern_text)
            return True

    tax_pattern = Pattern(
        name="za_tax_shape_pattern",
        regex=r'\b[012394]\d{9}\b',
        score=0.90
    )
    analyzer.registry.add_recognizer(
        SARSIdentifierFormatRecognizer(
            supported_entity="SARS_TAX_NUMBER",
            patterns=[tax_pattern],
            context=["tax", "vat", "sars", "tax reference", "vat number"]
        )
    )

    # 3. CIPC Registration Number Recognizer
    cipc_pattern = Pattern(
        name="cipc_pattern",
        regex=r'\b\d{4}/\d{6}/\d{2}\b',
        score=0.90
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="CIPC_REG_NUMBER",
            patterns=[cipc_pattern],
            context=["cipc", "registration", "company registration"]
        )
    )

    # 4. South African Mobile / Phone Number Recognizer
    za_phone_pattern = Pattern(
        name="za_phone_pattern",
        regex=r'(?:\+27|27|0)[\s\-]?\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b',
        score=0.85
    )
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[za_phone_pattern],
            context=["mobile", "phone", "tel", "cell", "direct", "contact"]
        )
    )

except ImportError:
    analyzer = None
    anonymizer = None


class GatekeeperPipeline:
    def __init__(self, raw_dir=None, output_dir=None, db_path=None, engagement_secret=None):
        base_dir = Path(__file__).resolve().parent
        self.raw_dir = Path(raw_dir) if raw_dir else base_dir / "raw_intake_data"
        self.output_dir = Path(output_dir) if output_dir else base_dir / "sanitized_output"
        self.quarantine_dir = self.output_dir / "quarantine"
        self.db_path = str(db_path) if db_path else str(base_dir / "gatekeeper_audit.duckdb")
        
        # --- DEAL-SCOPED HMAC CRYPTOGRAPHIC SECRET ---
        env_secret = os.environ.get("GATEKEEPER_ENGAGEMENT_KEY")
        if engagement_secret:
            self.engagement_key = engagement_secret.encode("utf-8")
        elif env_secret:
            self.engagement_key = env_secret.encode("utf-8")
        else:
            self.engagement_key = secrets.token_bytes(32)
        
        self.raw_dir.mkdir(exist_ok=True, parents=True)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.quarantine_dir.mkdir(exist_ok=True, parents=True)
        
        self._init_db()

    def _init_db(self):
        conn = duckdb.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pre_flight_diagnostics (
                run_id VARCHAR,
                timestamp TIMESTAMP,
                original_filename VARCHAR,
                file_format VARCHAR,
                sheet_count INTEGER,
                raw_tokens INTEGER,
                total_pii_detected INTEGER,
                pii_breakdown_json VARCHAR
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                run_id VARCHAR,
                timestamp TIMESTAMP,
                original_filename VARCHAR,
                pseudonymized_filename VARCHAR,
                vdr_folder VARCHAR,
                functional_zone VARCHAR,
                file_hash_sha256 VARCHAR,
                entities_redacted_count INTEGER,
                tokens_before INTEGER,
                tokens_after INTEGER,
                token_savings_percent DECIMAL(5,2),
                status VARCHAR
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_mappings (
                entity_hmac_digest VARCHAR PRIMARY KEY,
                pseudonym_alias VARCHAR,
                entity_type VARCHAR,
                created_at TIMESTAMP
            )
        """)
        conn.close()

    def count_bpe_tokens(self, text: str) -> int:
        if _bpe_encoder:
            return len(_bpe_encoder.encode(text))
        return max(1, len(text) // 4)

    def compute_sha256(self, file_path: Path) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def determine_vdr_and_zone(self, file_path: Path):
        rel_path = file_path.relative_to(self.raw_dir)
        vdr_folder = str(rel_path.parent) if str(rel_path.parent) != "." else "root"

        path_lower = str(rel_path).lower()
        ext = file_path.suffix.lower()

        if any(term in path_lower for term in ['financial', 'invoice', 'tax', 'vat', 'statement', 'balance', 'revenue']) or ext in ['.xlsx', '.csv']:
            subfolder = "spreadsheets" if ext in ['.xlsx', '.csv'] else "reports"
            zone = f"financials/{subfolder}"
        elif any(term in path_lower for term in ['contract', 'agreement', 'lease', 'cipc', 'legal', 'compliance', 'record']):
            subfolder = "contracts" if any(t in path_lower for t in ['contract', 'agreement', 'lease']) else "corporate_records"
            zone = f"legal/{subfolder}"
        elif ext in ['.png', '.jpg', '.jpeg']:
            zone = "scans/ocr_images"
        else:
            zone = "general/uncategorized"

        return vdr_folder, zone

    def generate_pseudonymized_name(self, original_stem: str, file_hash: str) -> str:
        clean_stem = "".join([c if c.isalnum() else "_" for c in original_stem.lower()])
        clean_stem = "_".join([part for part in clean_stem.split("_") if part])[:25]
        hash_suffix = file_hash[:6]
        return f"{clean_stem}_{hash_suffix}.txt"

    def get_or_create_hmac_alias(self, raw_value: str, entity_type: str, conn) -> str:
        """Cryptographic HMAC-SHA256 Pseudonymization Engine"""
        clean_val = raw_value.strip().lower().encode("utf-8")
        digest = hmac.new(self.engagement_key, clean_val, hashlib.sha256).hexdigest()
        
        row = conn.execute(
            "SELECT pseudonym_alias FROM entity_mappings WHERE entity_hmac_digest = ?", 
            [digest]
        ).fetchone()
        if row:
            return row[0]
        
        short_code = digest[:6].upper()
        alias = f"Individual_Entity_{short_code}" if entity_type == "PERSON" else f"<{entity_type}_{short_code}>"
            
        conn.execute(
            "INSERT INTO entity_mappings VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            [digest, alias, entity_type]
        )
        return alias

    def extract_text(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        text = ""
        
        if ext == ".pdf":
            if not pypdf:
                raise RuntimeError("Fail-Closed: 'pypdf' is not installed.")
            reader = pypdf.PdfReader(file_path)
            if reader.is_encrypted:
                raise ValueError("Fail-Closed: Encrypted or password-protected PDF quarantined.")
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += " ".join(extracted.split()) + "\n"

        elif ext == ".docx":
            if not docx:
                raise RuntimeError("Fail-Closed: 'python-docx' is not installed.")
            doc = docx.Document(file_path)
            for paragraph in doc.paragraphs:
                if paragraph.text.strip():
                    text += " ".join(paragraph.text.split()) + "\n"

        elif ext == ".xlsx":
            if not openpyxl:
                raise RuntimeError("Fail-Closed: 'openpyxl' is not installed.")
            wb = openpyxl.load_workbook(file_path, data_only=True)
            for sheet in wb.sheetnames:
                ws = wb[sheet]
                for row in ws.iter_rows(values_only=True):
                    cleaned_cells = []
                    for cell in row:
                        if cell is not None:
                            if isinstance(cell, float) and cell.is_integer():
                                cleaned_cells.append(str(int(cell)))
                            else:
                                cleaned_cells.append(str(cell).strip())
                    if cleaned_cells:
                        text += " ".join(cleaned_cells) + "\n"

        elif ext in ['.png', '.jpg', '.jpeg']:
            if not pytesseract or not Image:
                raise RuntimeError("Fail-Closed: 'pytesseract' or 'Pillow' is not installed.")
            with Image.open(file_path) as img:
                raw_ocr = pytesseract.image_to_string(img.convert('L'), config='--psm 6')
                lines = [" ".join(line.split()) for line in raw_ocr.splitlines() if line.strip()]
                text = "\n".join(lines)

        elif ext in ['.txt', '.md', '.csv']:
            with open(file_path, "r", encoding="utf-8", errors="strict") as f:
                text = f.read()
        else:
            raise ValueError(f"Fail-Closed: Unsupported file extension '{ext}'.")

        if not text.strip():
            raise ValueError("Fail-Closed: Extracted text payload is empty or unreadable.")

        return text

    def diagnose_file(self, file_path: Path) -> dict:
        if not analyzer:
            raise RuntimeError("Fail-Closed: Microsoft Presidio analyzer unavailable.")

        ext = file_path.suffix.lower()
        sheet_count = 0

        if ext == ".xlsx" and openpyxl:
            wb = openpyxl.load_workbook(file_path, read_only=True)
            sheet_count = len(wb.sheetnames)
            wb.close()

        raw_text = self.extract_text(file_path)
        raw_tokens = self.count_bpe_tokens(raw_text)

        target_entities = [
            "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS",
            "ZA_ID_NUMBER", "CIPC_REG_NUMBER", "SARS_TAX_NUMBER"
        ]
        results = analyzer.analyze(text=raw_text, entities=target_entities, language='en', score_threshold=0.80)

        pii_breakdown = {}
        for res in results:
            pii_breakdown[res.entity_type] = pii_breakdown.get(res.entity_type, 0) + 1

        return {
            "file_format": ext,
            "sheet_count": sheet_count,
            "raw_text": raw_text,
            "raw_tokens": raw_tokens,
            "total_pii": len(results),
            "pii_breakdown": pii_breakdown,
            "analyzer_results": results
        }

    def scrub_and_tokenize(self, text: str, pre_flight_results, conn):
        if not analyzer or not anonymizer:
            raise RuntimeError("Fail-Closed: Microsoft Presidio engines are unavailable.")

        target_entities = [
            "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", 
            "ZA_ID_NUMBER", "CIPC_REG_NUMBER", "SARS_TAX_NUMBER"
        ]

        operators = {
            "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED_SENSITIVE_DATA>"}),
            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE_NUMBER>"}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL_ADDRESS>"}),
            "ZA_ID_NUMBER": OperatorConfig("replace", {"new_value": "<ZA_ID_NUMBER>"}),
            "CIPC_REG_NUMBER": OperatorConfig("replace", {"new_value": "<CIPC_REG_NUMBER>"}),
            "SARS_TAX_NUMBER": OperatorConfig("replace", {"new_value": "<SARS_TAX_NUMBER>"}),
        }

        # Apply HMAC-SHA256 aliasing specifically for PERSON entities
        for res in sorted(pre_flight_results, key=lambda x: x.start, reverse=True):
            if res.entity_type == "PERSON":
                raw_name = text[res.start:res.end].strip()
                if len(raw_name) >= 4 and ' ' in raw_name and all(part.isalpha() for part in raw_name.split()):
                    alias = self.get_or_create_hmac_alias(raw_name, "PERSON", conn)
                    text = text[:res.start] + alias + text[res.end:]

        remaining_results = analyzer.analyze(
            text=text,
            entities=[e for e in target_entities if e != "PERSON"],
            language='en',
            score_threshold=0.80
        )
        anonymized_result = anonymizer.anonymize(text=text, analyzer_results=remaining_results, operators=operators)

        # --- INDIRECT PROMPT INJECTION SCRUBBING ---
        clean_scrubbed_text, _ = scrub_prompt_injections(anonymized_result.text)

        return clean_scrubbed_text, len(pre_flight_results)

    def process_pipeline(self):
        run_id = str(uuid.uuid4())[:8].upper()
        print(f"=== THE GATEKEEPER: AIRLOCK RUN [{run_id}] STARTING ===")
        files = [
            f for f in self.raw_dir.rglob("*")
            if f.is_file() and "sanitized_output" not in f.parts and not f.name.startswith(".")
        ]

        if not files:
            print(f"No files found in '{self.raw_dir}'.")
            return

        format_census = {}
        for f in files:
            ext = f.suffix.lower() or "<no_ext>"
            format_census[ext] = format_census.get(ext, 0) + 1

        print(f"[PRE-FLIGHT INTAKE CENSUS] Total Files: {len(files)} | Breakdown: {format_census}\n")

        conn = duckdb.connect(self.db_path)
        processed_count = 0
        skipped_count = 0
        quarantined_count = 0
        batch_pii_totals = {}
        total_sheets = 0
        total_tokens_before = 0
        total_tokens_after = 0

        for file_path in sorted(files):
            original_relative_path = file_path.relative_to(self.raw_dir)
            file_hash = self.compute_sha256(file_path)
            vdr_folder, functional_zone = self.determine_vdr_and_zone(file_path)
            
            existing = conn.execute(
                "SELECT pseudonymized_filename FROM audit_logs WHERE file_hash_sha256 = ? AND status LIKE 'SUCCESS%'", 
                [file_hash]
            ).fetchone()

            if existing:
                print(f"[SKIP DUPLICATE] {original_relative_path}")
                conn.execute("""
                    INSERT INTO audit_logs VALUES (
                        ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, 0, 0, 0, 0.0, 'SKIPPED_DUPLICATE'
                    )
                """, [run_id, str(original_relative_path), str(existing[0]), vdr_folder, "DUPLICATE_ARCHIVE", file_hash])
                skipped_count += 1
                continue

            try:
                diag = self.diagnose_file(file_path)
                total_sheets += diag["sheet_count"]
                for k, v in diag["pii_breakdown"].items():
                    batch_pii_totals[k] = batch_pii_totals.get(k, 0) + v

                conn.execute("""
                    INSERT INTO pre_flight_diagnostics VALUES (
                        ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?
                    )
                """, [
                    run_id, str(original_relative_path), diag["file_format"],
                    diag["sheet_count"], diag["raw_tokens"], diag["total_pii"],
                    json.dumps(diag["pii_breakdown"])
                ])

                pseudo_filename = self.generate_pseudonymized_name(file_path.stem, file_hash)

                tokens_before = diag["raw_tokens"]
                scrubbed_text, entity_count = self.scrub_and_tokenize(diag["raw_text"], diag["analyzer_results"], conn)
                tokens_after = self.count_bpe_tokens(scrubbed_text)
                savings_pct = round(((tokens_before - tokens_after) / max(tokens_before, 1)) * 100, 2)

                total_tokens_before += tokens_before
                total_tokens_after += tokens_after

                out_file = self.output_dir / functional_zone / vdr_folder / pseudo_filename if vdr_folder != "root" else self.output_dir / functional_zone / pseudo_filename
                out_file.parent.mkdir(exist_ok=True, parents=True)
                
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(scrubbed_text)

                print(f"[PROCESSED] {original_relative_path} -> {functional_zone} (PII: {diag['total_pii']} | Tokens: {tokens_before} -> {tokens_after})")

                conn.execute("""
                    INSERT INTO audit_logs VALUES (
                        ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                """, [
                    run_id, str(original_relative_path), str(pseudo_filename), vdr_folder, functional_zone,
                    file_hash, entity_count, tokens_before, tokens_after, savings_pct, "SUCCESS - FUNCTIONALLY ZONED"
                ])
                processed_count += 1

            except Exception as e:
                print(f"[QUARANTINED] {original_relative_path} -> Error: {str(e)}")
                quarantine_target = self.quarantine_dir / file_path.name
                shutil.copy2(file_path, quarantine_target)

                conn.execute("""
                    INSERT INTO audit_logs VALUES (
                        ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, 0, 0, 0, 0.0, ?
                    )
                """, [run_id, str(original_relative_path), "QUARANTINED", vdr_folder, "quarantine", file_hash, f"QUARANTINED - {str(e)}"])
                quarantined_count += 1

        avg_savings = round(((total_tokens_before - total_tokens_after) / max(total_tokens_before, 1)) * 100, 2)

        print("\n=== AIRLOCK DIAGNOSTIC & AUDIT SUMMARY ===")
        print(f"Pre-Flight Census     : {format_census} (Excel Tabs: {total_sheets})")
        print(f"Pre-Flight PII Risk   : {batch_pii_totals if batch_pii_totals else 'None Detected'}")
        print(f"Model-Aware Tokens    : {total_tokens_before:,} raw -> {total_tokens_after:,} clean ({avg_savings}% optimisation)")
        print(f"Post-Flight Routing   : Processed {processed_count} | Skipped {skipped_count} | Quarantined {quarantined_count}")
        print("==========================================")
        conn.close()


if __name__ == "__main__":
    gatekeeper = GatekeeperPipeline()
    gatekeeper.process_pipeline()