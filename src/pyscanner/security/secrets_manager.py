from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel


class SecretStore(BaseModel):
    """Store API keys encrypted at rest with a machine-local key file."""

    key_file: Path
    secrets_file: Path

    def _fernet(self) -> Fernet:
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.key_file.exists():
            self.key_file.write_bytes(Fernet.generate_key())
        key = self.key_file.read_bytes().strip()
        return Fernet(key)

    def set_secret(self, name: str, value: str) -> None:
        f = self._fernet()
        self.secrets_file.parent.mkdir(parents=True, exist_ok=True)
        blob: dict[str, str] = {}
        if self.secrets_file.exists():
            import json

            try:
                raw = json.loads(self.secrets_file.read_text())
                if isinstance(raw, dict):
                    blob = {k: str(v) for k, v in raw.items()}
            except (json.JSONDecodeError, OSError):
                blob = {}
        token = f.encrypt(value.encode()).decode()
        blob[name] = token
        import json

        self.secrets_file.write_text(json.dumps(blob))

    def get_secret(self, name: str) -> str | None:
        if not self.secrets_file.exists():
            return os.environ.get(name.upper())
        import json

        try:
            blob = json.loads(self.secrets_file.read_text())
        except (json.JSONDecodeError, OSError):
            return os.environ.get(name.upper())
        token = blob.get(name)
        if not token:
            return os.environ.get(name.upper())
        try:
            return self._fernet().decrypt(token.encode()).decode()
        except InvalidToken:
            return None
