import logging
import os
import subprocess
import tempfile

import pytest

__all__ = ['with_layout_comparison', 'compare_output']

from pyhanko.pdf_utils.writer import BasePdfFileWriter

logger = logging.getLogger(__name__)

SKIP_LAYOUT = False
SKIP_LAYOUT_REASON = "pdftoppm or compare tool path not specified"
pdftoppm_path = os.environ.get('PDFTOPPM_PATH', None)
compare_path = os.environ.get('IM_COMPARE_PATH', None)

if not pdftoppm_path or not compare_path:
    logger.warning(f"Skipping layout tests --- {SKIP_LAYOUT_REASON}")
    SKIP_LAYOUT = True

with_layout_comparison = pytest.mark.skipif(
    SKIP_LAYOUT, reason=SKIP_LAYOUT_REASON
)


def _render_pdf(pdf_file, out_file_prefix):
    # render the first page of a PDF to PNG file using pdftoppm
    result = subprocess.run(
        [pdftoppm_path, '-singlefile', '-png', pdf_file, out_file_prefix]
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to convert {pdf_file} to {out_file_prefix}.png using "
            f"pdftoppm (executable: {pdftoppm_path})."
        )
    return f"{out_file_prefix}.png"


def compare_output(writer: BasePdfFileWriter, expected_output_path):
    with tempfile.TemporaryDirectory() as working_dir:
        output_path = os.path.join(working_dir, 'output.pdf')
        with open(output_path, 'wb') as outf:
            writer.write(outf)
        expected_png = _render_pdf(
            expected_output_path, os.path.join(working_dir, 'expected')
        )
        actual_png = _render_pdf(
            output_path, os.path.join(working_dir, 'actual')
        )
        result = subprocess.run(
            # use the Absolute Error metric, since it's a single number
            # and hence very easy to process
            [
                compare_path, '-metric', 'ae',
                expected_png, actual_png, os.path.join(working_dir, 'diff.png')
            ],
            capture_output=True
        )
        # TODO maintain a directory of failed test outputs?
        if result.stderr != b'0':
            raise RuntimeError(
                f"Output compare test failed --- absolute error: "
                f"{result.stderr.decode('utf8')}"
            )
