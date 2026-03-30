from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> None:
    bridge = PROJECT_ROOT / "scripts" / "start_fluentbit_bridge.sh"
    local_conf = PROJECT_ROOT / "config" / "fluent-bit.conf"
    rpi_conf = PROJECT_ROOT / "config" / "fluent-bit-rpi.conf"
    payload = {
        "bridge_script_exists": bridge.exists(),
        "local_config_exists": local_conf.exists(),
        "rpi_config_exists": rpi_conf.exists(),
        "fluent_bit_binary_found": shutil.which("fluent-bit") is not None,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
