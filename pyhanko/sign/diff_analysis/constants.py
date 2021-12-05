"""
Internal constants for the difference analysis sub-package.
"""

import re

__all__ = [
    'ACROFORM_EXEMPT_STRICT_COMPARISON',
    'ROOT_EXEMPT_STRICT_COMPARISON',
    'FORMFIELD_ALWAYS_MODIFIABLE',
    'VALUE_UPDATE_KEYS',
    'VRI_KEY_PATTERN'
]


# /Ff: Form field flags can always be updated
FORMFIELD_ALWAYS_MODIFIABLE = {'/Ff'}


# /AP: appearance dictionary
# /AS: current appearance state
# /V: field value
# /F: (widget) annotation flags
# /DA: default appearance
# /Q: quadding
VALUE_UPDATE_KEYS = (
    FORMFIELD_ALWAYS_MODIFIABLE | {'/AP', '/AS', '/V', '/F', '/DA', '/Q'}
)


VRI_KEY_PATTERN = re.compile('/[A-Z0-9]{40}')


ACROFORM_EXEMPT_STRICT_COMPARISON = {
    '/Fields', '/DR', '/DA', '/Q', '/NeedAppearances'
}


ROOT_EXEMPT_STRICT_COMPARISON = {
    '/AcroForm', '/DSS', '/Extensions', '/Metadata', '/MarkInfo', '/Version'
}
