"""
Internal constants for the difference analysis sub-package.
"""

import re

__all__ = [
    'ACROFORM_EXEMPT_STRICT_COMPARISON',
    'FORMFIELD_ALWAYS_MODIFIABLE',
    'ROOT_EXEMPT_STRICT_COMPARISON',
    'VALUE_UPDATE_KEYS',
    'VRI_KEY_PATTERN',
]

# /Type: dictionary type (can always be added if correct)
# /Ff: Form field flags
FORMFIELD_ALWAYS_MODIFIABLE = frozenset({'/Ff', '/Type'})

# /AP: appearance dictionary
# /AS: current appearance state
# /V: field value
# /F: (widget) annotation flags
# /DA: default appearance
# /Q: quadding
VALUE_UPDATE_KEYS = FORMFIELD_ALWAYS_MODIFIABLE | frozenset(
    {
        '/AP',
        '/AS',
        '/V',
        '/F',
        '/DA',
        '/Q',
    }
)

VRI_KEY_PATTERN = re.compile('/[A-Z0-9]{40}')

ACROFORM_EXEMPT_STRICT_COMPARISON = frozenset(
    {
        '/Fields',
        '/DR',
        '/DA',
        '/Q',
        '/NeedAppearances',
    }
)

ROOT_EXEMPT_STRICT_COMPARISON = frozenset(
    {
        '/AcroForm',
        '/DSS',
        '/Extensions',
        '/Metadata',
        '/MarkInfo',
        '/Version',
    }
)
