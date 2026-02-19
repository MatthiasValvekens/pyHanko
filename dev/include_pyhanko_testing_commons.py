from pathlib import Path
import shutil
import sys
import tomlkit
import re
from typing import Iterable

PROJECT_REGEX = re.compile(r"[a-zA-Z_-]+")

INTERNAL_COMMON =  Path("internal") / "common-test-utils" / "src" / "pyhanko_testing_commons"
DEFAULT_TARGET_PACKAGES = ("pyhanko", "pyhanko-cli")


def _package_dir(root: Path, package: str) -> Path:
    return root / "pkgs" / package


def is_common_dep(entry) -> bool:
    """Return True if the dependency entry refers to common-test-utils or its extras."""
    if not isinstance(entry, str):
        return False
    return entry == "common-test-utils" or entry.startswith("common-test-utils[")


def remove_common_test_utils_from_pyproject(pyproj_path: Path):
    with pyproj_path.open("r", encoding="utf8") as fh:
        doc = tomlkit.load(fh)

    for grp in ("testing-base", "testing"):
        arr = doc["dependency-groups"][grp]
        doc["dependency-groups"][grp] = [e for e in arr if not is_common_dep(e)]

    with pyproj_path.open("w", encoding="utf8") as fh:
        tomlkit.dump(doc, fh)


def copy_testing_commons_to_package(root: Path, pkg_name: str) -> None:
    pkg_dir = _package_dir(root, pkg_name)
    dest = pkg_dir / "pyhanko_testing_commons"

    # Remove existing dest if present to ensure copy is fresh
    if dest.exists():
        if dest.is_dir():
            shutil.rmtree(dest)
        else:
            dest.unlink()

    shutil.copytree(root / INTERNAL_COMMON, dest)
    print(f"Copied {root / INTERNAL_COMMON} -> {dest}")


def include_testing_commons(root: Path, packages: Iterable[str]) -> None:
    """High-level function to include the internal testing commons into the
    given packages. Modifies pyproject.toml as needed and copies the package
    into each package's src/ tree."""
    if not (root / INTERNAL_COMMON).exists():
        print(f"Internal testing commons not found at {root / INTERNAL_COMMON}")
        return

    for pkg in packages:
        pkg_dir = _package_dir(root, pkg)
        if not pkg_dir.exists():
            print(f"Skipping {pkg}: no such directory {pkg_dir}")
            continue

        pyproj = pkg_dir / "pyproject.toml"
        if not pyproj.exists():
            print(f"Skipping {pkg}: no pyproject.toml at {pyproj}")
            continue

        try:
            remove_common_test_utils_from_pyproject(pyproj)
            print(f"Updated {pyproj} to remove common-test-utils from dependency lists")
            copy_testing_commons_to_package(root, pkg)
        except Exception as e:
            print(f"Error processing {pkg}: {e}")
            raise


def run():
    repo_root = Path(__file__).resolve().parents[1]

    # If package names are provided on the command line, use those.
    # Otherwise, default to the built-in targets.
    if len(sys.argv) > 1:
        pkg_args = sys.argv[1:]
        for p in pkg_args:
            if not PROJECT_REGEX.fullmatch(p):
                raise ValueError(f"Expected package name, not {p!r}")
        target_pkgs = tuple(pkg_args)
    else:
        target_pkgs = DEFAULT_TARGET_PACKAGES

    include_testing_commons(repo_root, target_pkgs)


if __name__ == '__main__':
    run()
