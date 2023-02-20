from typing import List

from .cli import cli

__all__: List[str] = []


def launch():
    cli(prog_name='pyhanko')


if __name__ == '__main__':
    launch()
