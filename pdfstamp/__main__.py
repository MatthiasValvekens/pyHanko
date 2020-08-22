from .cli import cli

__all__ = []


def launch():
    cli(prog_name='pdfstamp')


if __name__ == '__main__':
    launch()