from typing import Any


class Settings:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            cls._instance._config = {}
        return cls._instance

    def set(self, key: str, value: Any) -> None:
        self._config[key] = value

    def get(self, key: str, default: Any = None):
        return self._config.get(key, default)

    @property
    def network(self) -> bytes:
        return self.get('network')

    @network.setter
    def network(self, value: bytes) -> None:
        self.set('network', value)
