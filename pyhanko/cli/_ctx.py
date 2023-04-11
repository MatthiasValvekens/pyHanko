from dataclasses import dataclass
from typing import Optional

from pyhanko.cli.config import CLIConfig
from pyhanko.sign import PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.stamp import BaseStampStyle


@dataclass
class CLIContext:
    sig_settings: Optional[PdfSignatureMetadata] = None
    config: Optional[CLIConfig] = None
    existing_fields_only: bool = False
    timestamp_url: Optional[str] = None
    stamp_style: Optional[BaseStampStyle] = None
    stamp_url: Optional[str] = None
    new_field_spec: Optional[SigFieldSpec] = None
    prefer_pss: bool = False
    detach_pem: bool = False
    lenient: bool = False
