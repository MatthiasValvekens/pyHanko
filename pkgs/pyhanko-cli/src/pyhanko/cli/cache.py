from pathlib import Path

from pyhanko.cli.config import CLIConfig


def get_cache_dir(cli_config: CLIConfig | None) -> Path:
    import platformdirs

    if cli_config is not None and cli_config.cache_dir is not None:
        cache_dir = cli_config.cache_dir
    else:
        cache_dir = platformdirs.user_cache_dir('pyhanko-cli')
    return Path(cache_dir)


def get_eutl_cache_dir(cli_config: CLIConfig | None) -> Path:
    p = get_cache_dir(cli_config) / 'eutl'
    return p
