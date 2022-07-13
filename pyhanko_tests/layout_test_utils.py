import logging
import os
import shutil
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


def _ensure_path(failed_tests_root, expected_output_path):
    out_dir = os.path.join(
        failed_tests_root,
        os.path.dirname(expected_output_path),
        os.path.basename(expected_output_path) + '_results'
    )
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    return out_dir


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
        if result.stderr != b'0':
            dest_dir = _ensure_path("failed_layout_tests", expected_output_path)
            shutil.copy(output_path, os.path.join(dest_dir, "output.pdf"))
            from_workdir = ('actual.png', 'diff.png', 'expected.png')
            for f in from_workdir:
                shutil.copy(
                    src=os.path.join(working_dir, f),
                    dst=os.path.join(dest_dir, f),
                    follow_symlinks=False
                )
            shutil.copy(os.path.join(working_dir, 'diff.png'), dest_dir)
            shutil.copy(os.path.join(working_dir, 'expected.png'), dest_dir)
            raise RuntimeError(
                f"Output compare test failed --- absolute error: "
                f"{result.stderr.decode('utf8')}; "
                f"Output saved in {dest_dir}."
            )
