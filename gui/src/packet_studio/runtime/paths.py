from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimeDirectories:
    config_dir: Path
    log_dir: Path
    cache_dir: Path


def _base_data_dir() -> Path:
    app_data = os.environ.get("APPDATA")
    if app_data:
        return Path(app_data)
    return Path.home() / ".config"


def _base_cache_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data)
    return Path.home() / ".cache"


def ensure_runtime_directories() -> RuntimeDirectories:
    base_config_dir = _base_data_dir() / "ScapyStudio"
    base_log_dir = base_config_dir / "logs"
    base_cache_dir = _base_cache_dir() / "ScapyStudio"

    for directory in [base_config_dir, base_log_dir, base_cache_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    return RuntimeDirectories(
        config_dir=base_config_dir,
        log_dir=base_log_dir,
        cache_dir=base_cache_dir,
    )