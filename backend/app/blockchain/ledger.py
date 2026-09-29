import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


class BlockchainLedger:

    def __init__(self, storage_path="data/blockchain/ledger.json"):
        self.storage_path = Path(storage_path)
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

    def verify_chain(self):

        chain = self._load_chain()

        for i, block in enumerate(chain):

            calculated_hash = self._calculate_hash(block)

            if block["hash"] != calculated_hash:
                return False

            if i > 0:
                previous_block = chain[i - 1]

                if block["previous_hash"] != previous_block["hash"]:
                    return False

        return True

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

                return {
                    "event_id": event_id,
                    "valid": (
                        block["event_hash"] == current_event_hash
                        and
                        block["raw_log_hash"] == current_raw_hash
                    ),
                    "stored_event_hash": block["event_hash"],
                    "current_event_hash": current_event_hash,
                    "stored_raw_log_hash": block["raw_log_hash"],
                    "current_raw_log_hash": current_raw_hash,
                }

        return {
            "event_id": event_id,
            "valid": False,
            "error": "Event not found in blockchain"
        }