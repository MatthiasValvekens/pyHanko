"""
Tests for PDF MAC, AKA ISO 32004.

Note: most of the failure cases follow "known bad" sample files.
"""

import asyncio
import enum
import functools
import hashlib
import itertools
import os
import re
import typing
from functools import wraps
from io import BytesIO
from typing import Callable, Optional, Type

import pytest
from asn1crypto import core
from certomancer.integrations.illusionist import Illusionist
from freezegun import freeze_time
from pyhanko.pdf_utils import generic, writer
from pyhanko.pdf_utils.crypt import (
    PubKeySecurityHandler,
    StandardSecurityHandler,
    pdfmac,
)
from pyhanko.pdf_utils.crypt.api import PdfMacStatus
from pyhanko.pdf_utils.font.basic import get_courier
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import (
    PdfSigner,
    PdfTimeStamper,
    SimpleSigner,
    signers,
    timestamps,
)
from pyhanko.sign.general import SigningError, simple_cms_attribute
from pyhanko.sign.signers import cms_embedder
from pyhanko.sign.signers.pdf_byterange import SigByteRangeObject
from pyhanko.sign.validation import (
    RevocationInfoValidationType,
    validate_pdf_ltv_signature,
)
from pyhanko.sign.validation.errors import DisallowedAlgorithmError
from requests_mock import Mocker

from pyhanko_certvalidator import ValidationContext

from .samples import *
from .signing_commons import (
    DUMMY_TS,
    ECC_ROOT_CERT,
    FROM_ECC_CA,
    SIMPLE_ECC_V_CONTEXT,
    val_trusted,
)

DUMMY_PASSWORD = "secret"


GENERATED_TEST_OUTPUTS: Optional[str] = None


def _dummy_decrypt(r: PdfFileReader, ignore_mac=False):
    if ignore_mac:
        r._validate_pdf_mac = id
    if isinstance(r.security_handler, PubKeySecurityHandler):
        result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    elif isinstance(r.security_handler, StandardSecurityHandler):
        result = r.decrypt(DUMMY_PASSWORD)
    else:
        raise NotImplementedError
    return result


def _fmt_arg(arg: typing.Any) -> str:
    # hacky helper function for choosing file names for test outputs
    if isinstance(arg, (int, bool)):
        return str(arg)
    elif isinstance(arg, str) and arg.isalnum():
        return arg
    elif isinstance(arg, enum.Enum):
        return f"{arg.__class__.__name__}_{arg.name}"
    elif isinstance(arg, Mocker):
        return ""  # ignore
    else:
        raise NotImplementedError(
            f"Test with bad argument of type {type(arg)}; "
            f"can't derive output file name"
        )


def _preserve_test_result(
    subfolder: str, name: str, output: BytesIO, test_kwargs: dict
):
    """
    Hook to preserve test outputs as reference files.
    """

    if not GENERATED_TEST_OUTPUTS:
        return

    out_dir = os.path.join(GENERATED_TEST_OUTPUTS, subfolder)
    fmt_args = (_fmt_arg(v) for v in test_kwargs.values())
    name_suffix = '-'.join(p for p in fmt_args if p)
    if name_suffix:
        out_dir = os.path.join(out_dir, name)
        fname = f"{name}-{name_suffix}"
    else:
        fname = name
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f"{fname}.pdf"), 'wb') as outf:
        outf.write(output.getvalue())


def pdf_mac_good(test_fun):
    @wraps(test_fun)
    def _wrap(*args, **kwargs):
        output_buf = test_fun(*args, **kwargs)
        r = PdfFileReader(output_buf)
        result = _dummy_decrypt(r)
        assert result.mac_status == PdfMacStatus.SUCCESSFUL
        iso_exts = {
            int(ext.get_object()['/ExtensionLevel'])
            for ext in r.root['/Extensions']['/ISO_']
        }
        assert 32004 in iso_exts
        _preserve_test_result("good", test_fun.__name__, output_buf, kwargs)

    return _wrap


def pdfmac_known_bad_case(error_message: str):
    def dec(test_fun):
        @wraps(test_fun)
        def _wrap(*args, **kwargs):
            output_buf = test_fun(*args, **kwargs)
            r = PdfFileReader(output_buf)
            result = _dummy_decrypt(r)
            assert result.mac_status == PdfMacStatus.FAILED
            match = re.search(
                error_message, result.mac_failure_reason, re.IGNORECASE
            )
            assert match is not None, (
                f"Error {result.mac_failure_reason!r} did "
                f"not match {error_message!r}"
            )
            _preserve_test_result("bad", test_fun.__name__, output_buf, kwargs)

        return _wrap

    return dec


def shallow_wraps(wrapped):
    # same as functools.wraps() but doesn't expose the arguments list
    # of the underlying function by omitting __wrapped__
    # (and the annotation list).
    # Use case: create canned parameterised tests using decorators
    # (since pytest.mark.parameterized is a little too clever with arglist
    # introspection)

    def dec(wrapper):
        assigned = ('__module__', '__name__', '__qualname__', '__doc__')
        updated = functools.WRAPPER_UPDATES
        for attr in assigned:
            try:
                value = getattr(wrapped, attr)
            except AttributeError:
                pass
            else:
                setattr(wrapper, attr, value)
        for attr in updated:
            getattr(wrapper, attr).update(getattr(wrapped, attr, {}))
        return wrapper

    return dec


# This is an enum to improve the readability of pytest output


class MacLocation(enum.Enum):
    STANDALONE = 0
    IN_SIG = 1


class EncryptionType(enum.Enum):
    STANDARD = 0
    PUBKEY = 1


def init_sample_doc(
    encryption_type: EncryptionType,
    writer_class: Type[PdfFileWriter] = PdfFileWriter,
):
    w = writer_class(stream_xrefs=False)

    resources = generic.DictionaryObject(
        {
            generic.pdf_name('/Font'): generic.DictionaryObject(
                {generic.pdf_name('/F1'): get_courier(w)}
            )
        }
    )

    stream_content = '''
    BT
        /F1 12 Tf 40 700 Td 12 TL
        (Hello ISO/TS 32004!) Tj
    ET
    '''

    stream = generic.StreamObject(stream_data=stream_content.encode('latin1'))
    explanation_page = writer.PageObject(
        contents=w.add_object(stream),
        media_box=(0, 0, 595.28, 841.89),
        resources=resources,
    )
    w.insert_page(explanation_page)

    if encryption_type == EncryptionType.PUBKEY:
        sh = PubKeySecurityHandler.build_from_certs(
            [PUBKEY_TEST_DECRYPTER.cert], compat_entries=False
        )
        w._assign_security_handler(sh)
    else:
        w.encrypt(DUMMY_PASSWORD, compat_entries=False)
    return w


def pdfmac_with_handler(
    error_message: str, only_location: Optional[MacLocation] = None
):
    """
    Decorator to set up a test (or multiple tests) based on an alternative
    Handler implementation. Used to exercise the validator.
    """

    if only_location is not None:
        locations = [only_location]
    else:
        locations = iter(MacLocation)

    def dec(test_fun):
        @pytest.mark.parametrize(
            'location,encryption_type',
            itertools.product(locations, iter(EncryptionType)),
        )
        @pdfmac_known_bad_case(error_message)
        @shallow_wraps(test_fun)
        def _wrap(location: MacLocation, encryption_type: EncryptionType):
            handler_cls: Type[pdfmac.PdfMacTokenHandler] = test_fun()
            w = init_sample_doc(encryption_type)
            w._mac_handler_cls = handler_cls

            if location == MacLocation.IN_SIG:
                signer = SimpleSigner(
                    signing_cert=FROM_ECC_CA.signing_cert,
                    signing_key=FROM_ECC_CA.signing_key,
                    cert_registry=FROM_ECC_CA.cert_registry,
                )
                out = signers.sign_pdf(
                    w,
                    signers.PdfSignatureMetadata(field_name='Sig'),
                    signer=signer,
                )
            else:
                out = BytesIO()
                w.write(out)

            return out

        return _wrap

    return dec


@pdf_mac_good
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_simple_mac(encryption_type):
    w = init_sample_doc(encryption_type)
    out = BytesIO()
    w.write(out)
    return out


@pdf_mac_good
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_simple_mac_nondefault_hash(encryption_type):
    w = init_sample_doc(encryption_type)

    class Handler(pdfmac.PdfMacTokenHandler):
        @classmethod
        def from_key_mat(
            cls, file_encryption_key: bytes, kdf_salt: bytes, md_algorithm: str
        ):
            mac_kek = cls._derive_mac_kek(file_encryption_key, kdf_salt)
            return cls(mac_kek=mac_kek, md_algorithm='sha384')

    w._mac_handler_cls = Handler
    out = BytesIO()
    w.write(out)
    return out


@freeze_time('2020-11-01')
@pdf_mac_good
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_sign_crypt_aes256_with_mac(encryption_type):
    w = init_sample_doc(encryption_type)
    signer = SimpleSigner(
        signing_cert=FROM_ECC_CA.signing_cert,
        signing_key=FROM_ECC_CA.signing_key,
        cert_registry=FROM_ECC_CA.cert_registry,
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig'),
        signer=signer,
    )

    r = PdfFileReader(out)
    _dummy_decrypt(r)
    s = r.embedded_signatures[0]
    val_trusted(s, vc=SIMPLE_ECC_V_CONTEXT())
    return out


@pdf_mac_good
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_signature_nondefault_hash(encryption_type):
    w = init_sample_doc(encryption_type)
    signer = SimpleSigner(
        signing_cert=FROM_ECC_CA.signing_cert,
        signing_key=FROM_ECC_CA.signing_key,
        cert_registry=FROM_ECC_CA.cert_registry,
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig', md_algorithm='sha384'),
        signer=signer,
    )

    return out


@pdf_mac_good
@freeze_time('2020-11-01')
def test_pdf_mac_pades(requests_mock):
    w = init_sample_doc(EncryptionType.STANDARD)

    trust_roots = [ECC_ROOT_CERT]
    vc = ValidationContext(
        trust_roots=trust_roots, allow_fetching=True, other_certs=[]
    )
    Illusionist(TESTING_CA_ECDSA).register(requests_mock)

    from .test_pades import PADES

    signer = SimpleSigner(
        signing_cert=FROM_ECC_CA.signing_cert,
        signing_key=FROM_ECC_CA.signing_key,
        cert_registry=FROM_ECC_CA.cert_registry,
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            validation_context=vc,
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        timestamper=timestamps.HTTPTimeStamper(
            'http://pyhanko.tests/testing-ca-ecdsa/tsa/tsa',
        ),
        signer=signer,
    )

    r = PdfFileReader(out)
    r.decrypt(DUMMY_PASSWORD)
    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LTA,
        validation_context_kwargs={
            'trust_roots': trust_roots,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )
    return out


@pdf_mac_good
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
@freeze_time('2020-11-01')
def test_pdf_mac_timestamp(encryption_type):
    w = init_sample_doc(EncryptionType.STANDARD)
    out = BytesIO()
    w.write(out)

    w = IncrementalPdfFileWriter(out)
    w.encrypt("secret")
    PdfTimeStamper(timestamper=DUMMY_TS).timestamp_pdf(
        w, md_algorithm='sha256', in_place=True
    )
    return out


@pdf_mac_good
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_cms_algorithm_protection_attr_missing(encryption_type):
    # this is actually allowed, it's a 'should' in ISO 32004

    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                    simple_cms_attribute('message_digest', message_digest),
                ]
            )

    w = init_sample_doc(encryption_type)
    w._mac_handler_cls = Handler
    out = BytesIO()
    w.write(out)

    return out


@pdfmac_known_bad_case("Document digest does not match")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_standalone_mac_tamper(encryption_type):
    w = init_sample_doc(encryption_type)
    out = BytesIO()
    w.write(out)
    # this is in the middle of the second line of the header, so pretty benign
    out.seek(10)
    out.write(b'\x01')
    return out


@pdfmac_with_handler("Failed to unwrap")
def test_alter_key():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _get_mac_keying_info(self, dry_run):
            mac_key, ri = super()._get_mac_keying_info(dry_run)
            # by altering the key record, we mess up the unwrapping later
            ek = ri.chosen['encrypted_key']
            ri.chosen['encrypted_key'] = bytes(reversed(ek.native))
            return mac_key, ri

    return Handler


@pdfmac_with_handler("Failed to unwrap")
def test_alter_salt():
    class Handler(pdfmac.PdfMacTokenHandler):
        @classmethod
        def from_key_mat(
            cls, file_encryption_key: bytes, kdf_salt: bytes, md_algorithm: str
        ):
            return super().from_key_mat(
                file_encryption_key=file_encryption_key,
                # do calculations with a different salt
                kdf_salt=bytes(32),
                md_algorithm=md_algorithm,
            )

    return Handler


@pdfmac_with_handler("token has invalid MAC")
def test_append_auth_attr():
    class Handler(pdfmac.PdfMacTokenHandler):
        def compute_mac(self, mac_key: bytes, data_to_mac: bytes) -> bytes:
            # the point of this one is that the MAC was computed
            # over a different set of authenticated attributes,
            # so we might as well mess with the MAC computation instead
            return super().compute_mac(
                mac_key=mac_key, data_to_mac=cms.CMSAttributes([]).dump()
            )

    return Handler


@pdfmac_with_handler("Multiple CMS algorithm protection attributes present")
def test_cms_algorithm_protection_attr_multival():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            algo_protection = cms.CMSAlgorithmProtection(
                {
                    'mac_algorithm': self.mac_algo_ident,
                    'digest_algorithm': cms.DigestAlgorithm(
                        {'algorithm': self.md_algorithm}
                    ),
                }
            )
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                    simple_cms_attribute('message_digest', message_digest),
                    cms.CMSAttribute(
                        {
                            'type': cms.CMSAttributeType(
                                'cms_algorithm_protection'
                            ),
                            'values': (algo_protection, algo_protection),
                        }
                    ),
                ]
            )

    return Handler


@pdfmac_with_handler("duplicated")
def test_cms_algorithm_protection_attr_duplicated():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            algo_protection = cms.CMSAlgorithmProtection(
                {
                    'mac_algorithm': self.mac_algo_ident,
                    'digest_algorithm': cms.DigestAlgorithm(
                        {'algorithm': self.md_algorithm}
                    ),
                }
            )
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                    simple_cms_attribute('message_digest', message_digest),
                    simple_cms_attribute(
                        'cms_algorithm_protection', algo_protection
                    ),
                    simple_cms_attribute(
                        'cms_algorithm_protection', algo_protection
                    ),
                ]
            )

    return Handler


@pdfmac_with_handler("Digest algorithm does not match")
def test_cms_algorithm_protection_digest_algo_mismatch():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            algo_protection = cms.CMSAlgorithmProtection(
                {
                    'mac_algorithm': self.mac_algo_ident,
                    'digest_algorithm': cms.DigestAlgorithm(
                        {'algorithm': 'sha3_512'}
                    ),
                }
            )
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                    simple_cms_attribute('message_digest', message_digest),
                    simple_cms_attribute(
                        'cms_algorithm_protection', algo_protection
                    ),
                ]
            )

    return Handler


@pdfmac_with_handler("MAC mechanism does not match")
def test_cms_algorithm_protection_mac_algo_mismatch():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            algo_protection = cms.CMSAlgorithmProtection(
                {
                    'mac_algorithm': cms.HmacAlgorithm({'algorithm': 'sha512'}),
                    'digest_algorithm': cms.DigestAlgorithm(
                        {'algorithm': self.md_algorithm}
                    ),
                }
            )
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                    simple_cms_attribute('message_digest', message_digest),
                    simple_cms_attribute(
                        'cms_algorithm_protection', algo_protection
                    ),
                ]
            )

    return Handler


@pdfmac_with_handler("attribute not valid for authenticated data")
def test_cms_algorithm_protection_mac_algo_missing():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            algo_protection = cms.CMSAlgorithmProtection(
                {
                    'digest_algorithm': cms.DigestAlgorithm(
                        {'algorithm': self.md_algorithm}
                    ),
                }
            )
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                    simple_cms_attribute('message_digest', message_digest),
                    simple_cms_attribute(
                        'cms_algorithm_protection', algo_protection
                    ),
                ]
            )

    return Handler


@pdfmac_with_handler("Content type not found in authenticated attributes")
def test_duplicate_content_type_attr():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            return cms.CMSAttributes(
                [
                    cms.CMSAttribute(
                        {
                            'type': cms.CMSAttributeType('content_type'),
                            'values': ('data', 'pdf_mac_integrity_info'),
                        }
                    ),
                    simple_cms_attribute('message_digest', message_digest),
                ]
            )

    return Handler


@pdfmac_with_handler("Content type not found in authenticated attributes")
def test_no_content_type_attr():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            return cms.CMSAttributes(
                [
                    simple_cms_attribute('message_digest', message_digest),
                ]
            )

    return Handler


@pdfmac_with_handler("content type.*must be id-pdfMacIntegrityInfo")
def test_wrong_content_type_attr():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            return cms.CMSAttributes(
                [
                    simple_cms_attribute('content_type', 'data'),
                    simple_cms_attribute('message_digest', message_digest),
                ]
            )

    return Handler


@pdfmac_with_handler("Message digest not found")
def test_no_md():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                ]
            )

    return Handler


@pdfmac_with_handler("messageDigest attribute does not match")
def test_bad_md():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            dummy = hashlib.sha256(b'\xde\xad\xbe\xef').digest()
            return cms.CMSAttributes(
                [
                    simple_cms_attribute(
                        'content_type', 'pdf_mac_integrity_info'
                    ),
                    simple_cms_attribute('message_digest', dummy),
                ]
            )

    return Handler


@pdfmac_with_handler("PDF MAC tokens cannot have unauthenticated attributes")
def test_with_unauth_attrs():
    class Handler(pdfmac.PdfMacTokenHandler):
        def build_pdfmac_token(self, *args, **kwargs) -> cms.ContentInfo:
            token = super().build_pdfmac_token(*args, **kwargs)
            # doesn't have to make any sense
            token['content']['unauth_attrs'] = cms.CMSAttributes(
                [simple_cms_attribute('content_type', 'data')]
            )
            return token

    return Handler


@pdfmac_with_handler("key derivation.*identified as pdfMacWrapKdf")
def test_no_kdf():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _get_mac_keying_info(self, dry_run):
            mac_key, ri = super()._get_mac_keying_info(dry_run)
            del ri.chosen['key_derivation_algorithm']
            return mac_key, ri

    return Handler


@pdfmac_with_handler("requires exactly one recipientInfo")
def test_too_many_recipients():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_data(self, *args, **kwargs) -> cms.AuthenticatedData:
            ad = super()._format_auth_data(*args, **kwargs)
            ris = ad['recipient_infos']
            ris.append(ris[0])
            return ad

    return Handler


@pdfmac_with_handler("must be.*PasswordRecipientInfo")
def test_wrong_recipient_type():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_data(
            self, recipient_info, *args, **kwargs
        ) -> cms.AuthenticatedData:
            return super()._format_auth_data(
                recipient_info=cms.RecipientInfo(
                    {
                        'ori': cms.OtherRecipientInfo(
                            {
                                'ori_type': '2.999',
                                'ori_value': core.OctetString(
                                    b'\xde\xad\xbe\xef'
                                ),
                            }
                        )
                    }
                ),
                *args,
                **kwargs,
            )

    return Handler


@pdfmac_with_handler("must be.*pdfMacIntegrityInfo")
def test_wrong_enc_content_type():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_auth_attrs(
            self, message_digest: bytes
        ) -> cms.CMSAttributes:
            # the signers we currently use in the tests will use SHA-384
            hash_fun = getattr(hashlib, self.md_algorithm)
            return super()._format_auth_attrs(
                hash_fun(b'\xde\xad\xbe\xef').digest()
            )

        def _format_auth_data(self, *args, **kwargs) -> cms.AuthenticatedData:
            ad = super()._format_auth_data(*args, **kwargs)
            ad['encap_content_info'] = cms.EncapsulatedContentInfo(
                {
                    'content_type': 'data',
                    'content': core.ParsableOctetString(b'\xde\xad\xbe\xef'),
                }
            )
            return ad

    return Handler


@pdfmac_with_handler("must be.*type AuthenticatedData")
def test_wrong_token_content_type():
    class Handler(pdfmac.PdfMacTokenHandler):
        def build_pdfmac_token(self, *args, **kwargs) -> cms.ContentInfo:
            return cms.ContentInfo(
                {
                    'content_type': 'data',
                    'content': core.OctetString(b'\xde\xad\xbe\xef'),
                }
            )

    return Handler


@pdfmac_with_handler(
    "unexpected signature digest", only_location=MacLocation.STANDALONE
)
def test_unexpected_sig_digest():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_message(self, document_digest, signature_digest):
            return super()._format_message(document_digest, document_digest)

    return Handler


@pdfmac_with_handler(
    "could not find signature digest", only_location=MacLocation.IN_SIG
)
def test_missing_sig_digest():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_message(self, document_digest, signature_digest):
            return super()._format_message(
                document_digest, signature_digest=None
            )

    return Handler


@pdfmac_with_handler(
    "Signature digest does not match value in", only_location=MacLocation.IN_SIG
)
def test_sig_wrong_sig_digest():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_message(self, document_digest, signature_digest):
            dummy = hashlib.sha256(b'\xde\xad\xbe\xef').digest()
            return super()._format_message(
                document_digest, signature_digest=dummy
            )

    return Handler


@pdfmac_with_handler(
    "Document digest does not match value in", only_location=MacLocation.IN_SIG
)
def test_sig_wrong_document_digest():
    class Handler(pdfmac.PdfMacTokenHandler):
        def _format_message(self, document_digest, signature_digest):
            dummy = hashlib.sha256(b'\xde\xad\xbe\xef').digest()
            return super()._format_message(
                dummy, signature_digest=signature_digest
            )

    return Handler


@pdfmac_with_handler(
    "must not have trailing CMS data", only_location=MacLocation.STANDALONE
)
def test_with_trailing_data():
    class Handler(pdfmac.PdfMacTokenHandler):
        def build_pdfmac_token(self, *args, dry_run: bool = False, **kwargs):
            token = super().build_pdfmac_token(*args, **kwargs, dry_run=dry_run)
            if dry_run:
                # just waste some space, this is only used for the estimate
                # anyhow, and all we need is an estimate that's a bit too large
                token['content']['unauth_attrs'] = cms.CMSAttributes(
                    [simple_cms_attribute('content_type', 'data')]
                )
            return token

    return Handler


@pdfmac_known_bad_case("Error retrieving salt")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_do_not_store_salt(encryption_type):
    w = init_sample_doc(encryption_type)
    del w._encrypt.get_object()['/KDFSalt']
    out = BytesIO()
    w.write(out)
    return out


@pdfmac_known_bad_case("must have /ByteRange covering the entire file")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_mac_no_full_coverage(encryption_type):
    w = init_sample_doc(encryption_type)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    _dummy_decrypt(r, ignore_mac=True)
    w = IncrementalPdfFileWriter.from_reader(r)
    # short-circuit MAC
    w.digest_aware_write = True
    w.root['/Foo'] = generic.pdf_name('/Bar')
    w.update_root()
    w.write_in_place()
    return out


@pdfmac_known_bad_case("must have /ByteRange covering the entire file")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_mac_with_signature_no_full_coverage(encryption_type):
    w = init_sample_doc(encryption_type)
    signer = SimpleSigner(
        signing_cert=FROM_ECC_CA.signing_cert,
        signing_key=FROM_ECC_CA.signing_key,
        cert_registry=FROM_ECC_CA.cert_registry,
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig'),
        signer=signer,
    )

    r = PdfFileReader(out)
    _dummy_decrypt(r, ignore_mac=True)
    w = IncrementalPdfFileWriter.from_reader(r)
    # short-circuit MAC
    w.digest_aware_write = True
    w.root['/Foo'] = generic.pdf_name('/Bar')
    w.update_root()
    w.write_in_place()
    return out


def test_simple_mac_weak_hash():
    w = init_sample_doc(EncryptionType.STANDARD)

    class Handler(pdfmac.PdfMacTokenHandler):
        @classmethod
        def from_key_mat(
            cls, file_encryption_key: bytes, kdf_salt: bytes, md_algorithm: str
        ):
            mac_kek = cls._derive_mac_kek(file_encryption_key, kdf_salt)
            return cls(mac_kek=mac_kek, md_algorithm='sha1')

    w._mac_handler_cls = Handler
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    with pytest.raises(DisallowedAlgorithmError):
        _dummy_decrypt(r)


@pdfmac_known_bad_case("Failed to locate AuthCode dictionary")
@pytest.mark.parametrize(
    'encryption_type,remove_salt',
    list(itertools.product(EncryptionType, [True, False])),
)
def test_stripped_mac_detected(encryption_type, remove_salt):
    class Writer(PdfFileWriter):
        def write(self, stream):
            # skip writing the MAC
            self._write(stream)

    w = init_sample_doc(encryption_type, writer_class=Writer)
    if remove_salt:
        del w._encrypt.get_object()['/KDFSalt']
    out = BytesIO()
    w.write(out)
    return out


@pdfmac_known_bad_case("AuthCode.*indirect")
@pytest.mark.parametrize(
    'encryption_type,mac_location',
    list(itertools.product(EncryptionType, MacLocation)),
)
def test_ac_dict_indirect(encryption_type, mac_location):
    class Writer(PdfFileWriter):
        def set_custom_trailer_entry(
            self, key: generic.NameObject, value: generic.PdfObject
        ):
            if key == '/AuthCode':
                value = self.add_object(value)
            super().set_custom_trailer_entry(key, value)

    w = init_sample_doc(encryption_type, writer_class=Writer)
    if mac_location == MacLocation.IN_SIG:
        signer = SimpleSigner(
            signing_cert=FROM_ECC_CA.signing_cert,
            signing_key=FROM_ECC_CA.signing_key,
            cert_registry=FROM_ECC_CA.cert_registry,
        )
        return signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig'),
            signer=signer,
        )
    else:
        out = BytesIO()
        w.write(out)
        return out


def _manipulate_with_sig(encryption_type, manipulator):
    class Writer(PdfFileWriter):
        def set_custom_trailer_entry(
            self, key: generic.NameObject, value: generic.PdfObject
        ):
            if key == '/AuthCode':
                assert isinstance(value, generic.DictionaryObject)
                manipulator(self, value)
            super().set_custom_trailer_entry(key, value)

    w = init_sample_doc(encryption_type, writer_class=Writer)

    signer = SimpleSigner(
        signing_cert=FROM_ECC_CA.signing_cert,
        signing_key=FROM_ECC_CA.signing_key,
        cert_registry=FROM_ECC_CA.cert_registry,
    )
    return signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig'),
        signer=signer,
    )


def _manipulate_standalone(encryption_type, manipulator):
    class Writer(PdfFileWriter):
        def set_custom_trailer_entry(
            self, key: generic.NameObject, value: generic.PdfObject
        ):
            if key == '/AuthCode':
                assert isinstance(value, generic.DictionaryObject)
                manipulator(self, value)
            super().set_custom_trailer_entry(key, value)

    w = init_sample_doc(encryption_type, writer_class=Writer)
    out = BytesIO()
    w.write(out)
    return out


@pdfmac_known_bad_case("requires /SigObjRef")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_missing_sig_ref(encryption_type):
    def manipulate(_w, value):
        del value['/SigObjRef']

    return _manipulate_with_sig(encryption_type, manipulator=manipulate)


@pdfmac_known_bad_case("must be an indirect reference")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_malformed_sig_ref_direct(encryption_type):
    def manipulate(_w, value):
        value['/SigObjRef'] = generic.DictionaryObject()

    return _manipulate_with_sig(encryption_type, manipulator=manipulate)


@pdfmac_known_bad_case("does not point to a dictionary")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_malformed_sig_ref_not_dictionary(encryption_type):
    def manipulate(w, value):
        value['/SigObjRef'] = w.add_object(generic.pdf_name('/Bleh'))

    return _manipulate_with_sig(encryption_type, manipulator=manipulate)


@pdfmac_known_bad_case("Failed to retrieve signature contents")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_malformed_sig_ref_not_signature(encryption_type):
    def manipulate(w, value):
        value['/SigObjRef'] = w.add_object(generic.DictionaryObject())

    return _manipulate_with_sig(encryption_type, manipulator=manipulate)


@pdfmac_known_bad_case("Failed to locate MAC in document")
def test_mac_location_missing():
    def manipulate(_w, value):
        del value['/MACLocation']

    return _manipulate_standalone(
        EncryptionType.STANDARD, manipulator=manipulate
    )


@pdfmac_known_bad_case("Failed to locate MAC in document")
def test_mac_location_unsupported():
    def manipulate(_w, value):
        value['/MACLocation'] = generic.pdf_name('/Bleh')

    return _manipulate_standalone(
        EncryptionType.STANDARD, manipulator=manipulate
    )


@pdfmac_known_bad_case("Failed to retrieve standalone MAC value")
@pytest.mark.parametrize('encryption_type', list(EncryptionType))
def test_mac_wrong_type(encryption_type):
    region_start_lazy: Optional[Callable[[], int]] = None

    def manipulate(_w, value):
        nonlocal region_start_lazy
        # we have to get a little creative here, since overriding the /MAC
        # field directly will break the serialisation logic
        region_start_lazy = lambda: value['/ByteRange'].first_region_len

    out = _manipulate_standalone(encryption_type, manipulator=manipulate)

    out.seek(region_start_lazy())
    out.write(b'/Bleh%')

    return out


@pdfmac_known_bad_case("No sensible /ByteRange found")
def test_byte_range_missing():
    # again, we need some creativity here
    br_obj = None

    def manipulate(_w, value):
        nonlocal br_obj
        br_obj = value['/ByteRange']

    out = _manipulate_standalone(
        EncryptionType.STANDARD, manipulator=manipulate
    )
    assert isinstance(br_obj, SigByteRangeObject)
    out.seek(br_obj._range_object_offset - 3)
    out.write(b'%\n/Bleh%')
    return out


def manipulatable_sign(manipulate_cms):
    # CMS-agnostic signing example
    #
    # write an in-place certification signature using the PdfCMSEmbedder
    # low-level API directly.

    w = init_sample_doc(EncryptionType.STANDARD)

    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)

    sig_obj = signers.SignatureObject(bytes_reserved=8192)

    md_algorithm = 'sha256'
    sig_obj_ref = cms_writer.send(
        cms_embedder.SigObjSetup(
            sig_placeholder=sig_obj,
        )
    )

    ac_dict = generic.DictionaryObject(
        {
            generic.pdf_name('/MACLocation'): generic.pdf_name(
                '/AttachedToSig'
            ),
            generic.pdf_name('/SigObjRef'): sig_obj_ref,
        }
    )
    w.set_custom_trailer_entry(generic.pdf_name('/AuthCode'), ac_dict)

    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm=md_algorithm)
    )

    signer: signers.SimpleSigner = FROM_ECC_CA
    content_info = asyncio.run(
        signer.async_sign(
            data_digest=prep_digest.document_digest,
            digest_algorithm=md_algorithm,
        )
    )
    manipulate_cms(content_info)
    cms_writer.send(content_info)

    return output


@pdfmac_known_bad_case("exactly 1 signerInfo")
def test_signer_info_cardinality_multi():
    def manipulate(ci):
        signer_infos = ci['content']['signer_infos']
        signer_infos.append(signer_infos[0])

    return manipulatable_sign(manipulate)


@pdfmac_known_bad_case("exactly 1 signerInfo")
def test_signer_info_cardinality_zero():
    def manipulate(ci):
        ci['content']['signer_infos'] = cms.SignerInfos([])

    return manipulatable_sign(manipulate)


@pdfmac_known_bad_case("exactly 1 pdfMacData unsigned attribute")
def test_pdf_mac_attr_missing():
    return manipulatable_sign(id)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel():
    w1 = init_sample_doc(EncryptionType.STANDARD)
    w2 = init_sample_doc(EncryptionType.STANDARD)
    signer = SimpleSigner(
        signing_cert=FROM_ECC_CA.signing_cert,
        signing_key=FROM_ECC_CA.signing_key,
        cert_registry=FROM_ECC_CA.cert_registry,
    )
    pdf_signer = PdfSigner(
        signers.PdfSignatureMetadata(field_name='Sig'),
        signer=signer,
        timestamper=DUMMY_TS,
    )

    with pytest.raises(
        SigningError, match='Other PDF MAC attribute provider found'
    ):
        await asyncio.gather(
            pdf_signer.async_sign_pdf(w1), pdf_signer.async_sign_pdf(w2)
        )
