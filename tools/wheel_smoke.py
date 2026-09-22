"""Run outside the checkout with the built wheel installed; no API access required."""

import importlib.metadata
import json
import subprocess
import sys
from importlib.resources import files


def main() -> None:
    requirement_names = importlib.metadata.requires("jevproc") or []
    assert not any(item.lower().startswith("rich") for item in requirement_names)
    assert files("jevproc").joinpath("data/default.yaml").is_file()
    assert files("jevproc").joinpath("data/demo-snapshot.json").is_file()
    result = subprocess.run(
        [sys.executable, "-m", "jevproc", "--demo", "--format", "json", "--fail-on", "none"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert report["mode"] == "demo" and report["summary"]["synthetic"]
    assert len(report["assessments"]) == 4
    assert report["summary"]["warnings"] == 1
    assert report["summary"]["uncertain_warnings"] == 1
    print("Installed wheel: resources, entry point, synthetic pipeline and JSON contract passed.")


if __name__ == "__main__":
    main()
