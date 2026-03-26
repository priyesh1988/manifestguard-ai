from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import yaml


@dataclass(slots=True)
class Defaults:
    db_path: Path = Path('.manifestguard/history.sqlite3')
    default_image_tag: str = '1.0.0'
    enable_learning: bool = True


def load_defaults(config_path: Path | None) -> Defaults:
    if not config_path or not config_path.exists():
        return Defaults()
    data = yaml.safe_load(config_path.read_text(encoding='utf-8')) or {}
    mg = data.get('manifestGuard') or {}
    return Defaults(
        db_path=Path(mg.get('dbPath', '.manifestguard/history.sqlite3')),
        default_image_tag=str(mg.get('defaultImageTag', '1.0.0')),
        enable_learning=bool(mg.get('enableLearning', True)),
    )
