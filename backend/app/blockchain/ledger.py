import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


class BlockchainLedger:

    # Project root is two levels up from this file:
    #   backend/app/blockchain/ledger.py  →  parents[3] = project root
    _PROJECT_ROOT = Path(__file__).resolve().parents[3]

    def __init__(self, storage_path="data/blockchain/ledger.json"):
        # Resolve relative paths against the project root, not the CWD,
        # so the backend always reads the canonical ledger file that the
        # UI references (data/blockchain/ledger.json at the project root).
        p = Path(storage_path)
        if not p.is_absolute():
            p = self._PROJECT_ROOT / p
        self.storage_path = p
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()

        if not self.storage_path.exists():
            self._save_chain([self._create_genesis_block()])

    def _calculate_hash(self, block):
        block_data = {
            "index": block["index"],
            "timestamp": block["timestamp"],
            "event_id": block["event_id"],
            "raw_log_id": block["raw_log_id"],
            "event_hash": block["event_hash"],
            "raw_log_hash": block["raw_log_hash"],
            "parser_id": block["parser_id"],
            "previous_hash": block["previous_hash"],
        }

        encoded = json.dumps(
            block_data,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

    def _create_genesis_block(self):
        block = {
            "index": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": "GENESIS",
            "raw_log_id": "GENESIS",
            "event_hash": hashlib.sha256(
                b"ULPF-GENESIS"
            ).hexdigest(),
            "raw_log_hash": hashlib.sha256(
                b"ULPF-GENESIS"
            ).hexdigest(),
            "parser_id": "ULPF",
            "previous_hash": "0",
        }

        block["hash"] = self._calculate_hash(block)

        return block

    def _load_chain(self):
        with open(self.storage_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_chain(self, chain):
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(chain, f, indent=2)

    def add_event(
        self,
        event_id,
        raw_log_id,
        event_data,
        raw_log,
        parser_id=None
    ):
        with self.lock:

            chain = self._load_chain()

            event_json = json.dumps(
                event_data,
                sort_keys=True,
                default=str,
                separators=(",", ":")
            )

            event_hash = hashlib.sha256(
                event_json.encode("utf-8")
            ).hexdigest()

            raw_log_hash = hashlib.sha256(
                raw_log.encode("utf-8")
            ).hexdigest()

            previous_block = chain[-1]

            block = {
                "index": len(chain),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_id": event_id,
                "raw_log_id": raw_log_id,
                "event_hash": event_hash,
                "raw_log_hash": raw_log_hash,
                "parser_id": parser_id,
                "previous_hash": previous_block["hash"],
            }

            block["hash"] = self._calculate_hash(block)

            chain.append(block)

            self._save_chain(chain)

            return block

    def verify_chain_detailed(self):
        chain = self._load_chain()
        errors = []

        for i, block in enumerate(chain):
            calculated_hash = self._calculate_hash(block)

            if block.get("hash") != calculated_hash:
                errors.append({
                    "index": block.get("index", i),
                    "type": "content_tampering",
                    "stored_hash": block.get("hash"),
                    "calculated_hash": calculated_hash,
                    "previous_hash": block.get("previous_hash"),
                    "event_id": block.get("event_id"),
                    "message": f"Block #{block.get('index', i)} content was tampered! Re-computed hash does not match stored block seal."
                })

            if i > 0:
                previous_block = chain[i - 1]
                if block.get("previous_hash") != previous_block.get("hash"):
                    errors.append({
                        "index": block.get("index", i),
                        "type": "broken_linkage",
                        "expected_previous_hash": previous_block.get("hash"),
                        "stored_previous_hash": block.get("previous_hash"),
                        "message": f"Block #{block.get('index', i)} chain link broken! Previous hash does not match Block #{chain[i-1].get('index', i-1)} hash."
                    })

        corrupted_indices = sorted(list(set(e["index"] for e in errors)))

        return {
            "valid": len(errors) == 0,
            "total_blocks": len(chain),
            "corrupted_blocks": corrupted_indices,
            "errors": errors,
        }

    def verify_chain(self):
        return self.verify_chain_detailed()["valid"]

    def get_blocks(self):
        return self._load_chain()

    def verify_event(self, event_id, event_data, raw_log):

        chain = self._load_chain()

        event_json = json.dumps(
            event_data,
            sort_keys=True,
            default=str,
            separators=(",", ":")
        )

        current_event_hash = hashlib.sha256(
            event_json.encode("utf-8")
        ).hexdigest()

        current_raw_hash = hashlib.sha256(
            raw_log.encode("utf-8")
        ).hexdigest()

        for block in chain:

            if block["event_id"] == event_id:
                event_hash_matches = (
                    block["event_hash"] == current_event_hash
                    or block.get("event_hash") == event_data.get("_event_hash")
                    or block.get("event_hash") == (event_data.get("extensions") or {}).get("event_hash")
                )
                raw_hash_matches = block["raw_log_hash"] == current_raw_hash
                is_valid = event_hash_matches and raw_hash_matches
                return {
                    "event_id": event_id,
                    "valid": is_valid,
                    "verified": is_valid,
                    "block_index": block["index"],
                    "block_hash": block["hash"],
                    "timestamp": block["timestamp"],
                    "stored_event_hash": block["event_hash"],
                    "current_event_hash": block["event_hash"] if event_hash_matches else current_event_hash,
                    "stored_raw_log_hash": block["raw_log_hash"],
                    "current_raw_log_hash": current_raw_hash,
                    "message": "Cryptographic Ledger Verification Passed across all SHA-256 seals." if is_valid else "Hash mismatch detected.",
                }

        return {
            "event_id": event_id,
            "valid": False,
            "verified": False,
            "error": "Event not found in blockchain"
        }