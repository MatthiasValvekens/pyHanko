from dataclasses import dataclass

from asn1crypto import x509
from freezegun import freeze_time
from pyhanko.config.pkcs11 import TokenCriteria
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import DisallowWeakAlgorithmsPolicy


@dataclass
class P11TestConfig:
    platform: str
    token_label: str
    module: str
    user_pin: str
    cert_label: str
    key_label: str | None
    algo: str
    cert_chain_labels: list[str]
    cert_chain: list[x509.Certificate]
    freeze_time_spec: str | None
    signing_pin: str | None

    @property
    def session(self):
        from pyhanko.sign import pkcs11

        return pkcs11.open_pkcs11_session(
            self.module,
            user_pin=self.user_pin,
            token_criteria=TokenCriteria(label=self.token_label),
        )

    @property
    def validation_context(self):
        kwargs = {
            'trust_roots': [self.cert_chain[0]],
            'other_certs': self.cert_chain[1:],
            'algorithm_usage_policy': DisallowWeakAlgorithmsPolicy(
                dsa_key_size_threshold=1024
            ),
        }
        if self.freeze_time_spec:
            with freeze_time('2020-11-01'):
                return ValidationContext(**kwargs)
        else:
            return ValidationContext(**kwargs)

    @property
    def signing_kwargs(self):
        signing_kwargs = {}
        if self.signing_pin is not None:
            signing_kwargs["pin"] = self.signing_pin
        return signing_kwargs
