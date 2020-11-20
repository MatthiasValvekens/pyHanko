from .cli import cli

__all__ = []


def launch():
    cli(prog_name='pyhanko')


if __name__ == '__main__':
    launch()