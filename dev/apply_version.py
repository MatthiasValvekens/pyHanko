import requests
import sys
import tomlkit
from pathlib import Path


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


def apply_version(root: Path, project: str, version: str):
    version_info_str = version.split('.', maxsplit=3)
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
    python_packages = (
        p
        for p in (project_dir / "src").iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )
    for pkg in python_packages:
        version_module = pkg / "version.py"
        version_package = pkg / "version" / "__init__.py"
        version_file = None
        if version_module.exists():
            version_file = version_module
        elif version_package.exists():
            version_file = version_package
        if version_file:
            print(f"Setting version info in {version_file}...")
            with open(version_file, "w") as versionf:
                versionf.write(f"__version__ = {version!r}\n")
                versionf.write(f"__version_info__ = {version_info!r}\n")


def run():
    repo_root = Path(__file__).resolve().parents[1]
    pkg_name = sys.argv[1]
    version = sys.argv[2]

    apply_version(repo_root, pkg_name, version)
    apply_latest_for_others(repo_root, pkg_name)


if __name__ == "__main__":
    run()
