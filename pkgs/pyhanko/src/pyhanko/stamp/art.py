from pyhanko.pdf_utils import content, layout

__all__ = ['STAMP_ART_CONTENT']

STAMP_ART_CONTENT = content.RawContent(
    box=layout.BoxConstraints(width=100, height=100),
    data=b'''
q 1 0 0 -1 0 100 cm
0.603922 0.345098 0.54902 rg
3.699 65.215 m 3.699 65.215 2.375 57.277 7.668 51.984 c 12.957 46.695 27.512
 49.34 39.418 41.402 c 39.418 41.402 31.48 40.078 32.801 33.465 c 34.125
 26.852 39.418 28.172 39.418 24.203 c 39.418 20.234 30.156 17.59 30.156
14.945 c 30.156 12.297 28.465 1.715 50 1.715 c 71.535 1.715 69.844 12.297
 69.844 14.945 c 69.844 17.59 60.582 20.234 60.582 24.203 c 60.582 28.172
 65.875 26.852 67.199 33.465 c 68.52 40.078 60.582 41.402 60.582 41.402
c 72.488 49.34 87.043 46.695 92.332 51.984 c 97.625 57.277 96.301 65.215
 96.301 65.215 c h f
3.801 68.734 92.398 7.391 re f
3.801 79.512 92.398 7.391 re f
3.801 90.289 92.398 7.391 re f
Q
''',
)
"""
Hardcoded stamp background that will render a stylised image of a stamp using
PDF graphics operators (see below).

.. image:: images/stamp-background.svg
   :alt: Standard stamp background
   :align: center

"""
