import re
import sys
from pathlib import Path

import requests
import tomlkit

PROJECT_REGEX = re.compile("[a-zA-Z_-]+")


def _other_projects(root: Path, project: str):
    return (
        p
        for p in (root / "pkgs").iterdir()
        if p.is_dir() and p.name != project and not p.name.startswith(".")
    )


def get_latest_version(project: str) -> str:
    url = f"https://pypi.org/pypi/{project}/json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()['info']['version']
    else:
        raise ValueError("Could not get latest version")


def apply_latest(root: Path, project: str):
    try:
        latest = get_latest_version(project)
    except ValueError:
        return
    apply_version(root, project, latest)


def apply_latest_for_others(root: Path, project: str):
    for other_proj in _other_projects(root, project):
        apply_latest(root, other_proj.name)


def version_file_candidates(project_dir: Path):
    python_packages = [
        p
        for p in (project_dir / "src").iterdir()
        if p.is_dir() and ("." not in p.name)
    ]

    # First check version.py and version/__init__.py
    # in top-level packages
    for pkg in python_packages:
        yield pkg / "version.py"
        yield pkg / "version" / "__init__.py"

    # then look for version.py in subpackages
    for pkg in python_packages:
        pkgs = sorted(pkg.iterdir(), key=lambda p: p.name)
        for sub_pkg in pkgs:
            yield sub_pkg / "version.py"


def apply_version(root: Path, project: str, version: str):
    version_info_str = version.split('.', maxsplit=3)
    if len(version_info_str) < 3:
        raise ValueError(
            f"Don't know how to interpret {version!r} as a version number"
        )
    major = int(version_info_str[0])
    minor = int(version_info_str[1])
    patch = int(version_info_str[2])

    if len(version_info_str) == 3:
        version_info = (major, minor, patch)
    else:
        version_info = (major, minor, patch, version_info_str[3])

    project_dir = root / "pkgs" / project
    # set the version in the main pyproject.toml
    print(f"Reading {project_dir / 'pyproject.toml'}...")
    with open(project_dir / "pyproject.toml", "r") as pyproj:
        pyproj_content = tomlkit.load(pyproj)
    pyproj_content["project"]["version"] = version

    print(f"Setting project.version for {project} to {version}")
    with open(project_dir / "pyproject.toml", "w") as pyproj:
        tomlkit.dump(pyproj_content, pyproj)

    # walk through dependent project to set the version in the downstream dependency declarations
    for other_proj in _other_projects(root, project):

        with open(other_proj / "pyproject.toml", "r") as pyproj:
            pyproj_content = tomlkit.load(pyproj)

        dep_arrs = (
            pyproj_content["project"]["dependencies"],
            *pyproj_content["project"].get("optional-dependencies", ()),
        )

        modified = False
        for dep_arr in dep_arrs:
            for ix, dep in enumerate(dep_arr):
                if dep == project:
                    dep_str = f"{project}>={major}.{minor}.{patch},<{major}.{minor + 1}"
                    print(
                        f"Setting dependency constraint {dep_str} in {other_proj.name}"
                    )
                    modified = True
                    dep_arr[ix] = dep_str
                    break
        if modified:
            with open(other_proj / "pyproject.toml", "w") as pyproj:
                tomlkit.dump(pyproj_content, pyproj)

    # set the version in version.py
    try:
        version_file = next(
            p for p in version_file_candidates(project_dir) if p.exists()
        )
        print(f"Setting version info for {project} in {version_file}...")
        with open(version_file, "w") as versionf:
            versionf.write(f"__version__ = {version!r}\n")
            versionf.write(f"__version_info__ = {version_info!r}\n")
    except StopIteration:
        raise ValueError(f"Version file for {project} not found")


def run():
    repo_root = Path(__file__).resolve().parents[1]
    pkg_name = sys.argv[1]
    if not PROJECT_REGEX.fullmatch(pkg_name):
        raise ValueError(f"Expected package name, not {pkg_name!r}")
    version = sys.argv[2]

    apply_version(repo_root, pkg_name, version)
    apply_latest_for_others(repo_root, pkg_name)


if __name__ == "__main__":
    run()
