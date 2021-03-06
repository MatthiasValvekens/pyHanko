"""
This module defines constants & defaults used by pyHanko when creating digital
signatures.
"""

from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.stamp import TextStampStyle, STAMP_ART_CONTENT


__all__ = [
    'DEFAULT_MD', 'DEFAULT_SIG_SUBFILTER', 'DEFAULT_SIGNER_KEY_USAGE',
    'SIG_DETAILS_DEFAULT_TEMPLATE', 'DEFAULT_SIGNING_STAMP_STYLE'
]


DEFAULT_SIG_SUBFILTER = SigSeedSubFilter.ADOBE_PKCS7_DETACHED
"""
Default SubFilter to use for a PDF signature.
"""

# TODO I've encountered TSAs that will spew invalid timestamps when presented
#  with a sha512 req (Adobe Reader agrees).
#  Should get to the bottom of that. In the meantime, default to sha256
DEFAULT_MD = 'sha256'
"""
Default message digest algorithm used when computing digests for use in
signatures.
"""

DEFAULT_SIGNER_KEY_USAGE = {"non_repudiation"}
"""
Default key usage bits required for the signer's certificate.
"""


SIG_DETAILS_DEFAULT_TEMPLATE = (
    'Digitally signed by %(signer)s.\n'
    'Timestamp: %(ts)s.'
)
"""
Default template string for signature appearances.
"""

DEFAULT_SIGNING_STAMP_STYLE = TextStampStyle(
    stamp_text=SIG_DETAILS_DEFAULT_TEMPLATE, background=STAMP_ART_CONTENT
)
"""
Default stamp style used for visible signatures.
"""
