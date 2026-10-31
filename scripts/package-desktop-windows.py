"""Package the desktop and headless worker together, without shell evaluation."""
from pathlib import Path
import sys
from zipfile import ZIP_DEFLATED, ZipFile


def main() -> None:
    target, output = sys.argv[1:]
    if target != "x86_64-pc-windows-msvc":
        raise ValueError("unsupported Windows desktop target")
    binaries = [Path("target") / target / "release" / name
                for name in ("nullguard-desktop.exe", "nullguard-worker.exe")]
    if not all(path.is_file() for path in binaries):
        raise FileNotFoundError("build both desktop and worker before packaging")
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination / "nullguard-desktop-windows.zip", "w", ZIP_DEFLATED) as archive:
        for path in binaries:
            archive.write(path, arcname=path.name)


if __name__ == "__main__":
    main()
