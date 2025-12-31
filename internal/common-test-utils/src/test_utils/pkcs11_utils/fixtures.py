import logging
import os
from pathlib import Path

import pytest
import yaml
from asn1crypto import x509
from freezegun import freeze_time
from pyhanko.config.pkcs11 import TokenCriteria
from pyhanko.keys import load_cert_from_pemder

from .config import P11TestConfig

__all__ = [
    'DEFAULT_SUPPORTED_ALGOS',
    'any_algo',
    'declared_algo',
    'platform',
    'p11_global_test_config',
    'p11_config',
    'p11_session',
]

DEFAULT_SUPPORTED_ALGOS = frozenset({'rsa', 'dsa', 'ecdsa', 'ed25519', 'ed448'})


@pytest.fixture(
    params=[
        pytest.param(k, marks=pytest.mark.algo(k))
        for k in DEFAULT_SUPPORTED_ALGOS
    ]
)
def any_algo(request):
    return request.param


@pytest.fixture
def declared_algo(request):
    for mark in request.node.iter_markers(name='algo'):
        return mark.args[0]
    return 'default'


def _available_platforms():
    if config_file := os.environ.get('PKCS11_CONFIG', None):
        with open(config_file, 'r') as inf:
            config_yaml = yaml.safe_load(inf)
            # Allow limiting the set of supported platforms with an env var.
            # The idea is to set this env var in the CI workflow definition,
            # so that CI doesn't break while new test devices are being
            # onboarded.
            env_limit = frozenset(
                os.environ.get('PKCS11_PLATFORMS', '').split(',')
            )
            key_set = frozenset(config_yaml.keys())
            if env_limit:
                return key_set & env_limit
            else:
                return key_set
    else:
        return frozenset({'softhsm'})


@pytest.fixture(scope='session', params=_available_platforms())
def platform(request):
    return request.param


@pytest.fixture(scope='session')
def p11_global_test_config(platform):
    if config_file := os.environ.get('PKCS11_CONFIG', None):
        configs = {}
        with open(config_file, 'r') as inf:
            config_yaml = yaml.safe_load(inf)
            platform_cfg = config_yaml[platform]
            for algo, cfg in platform_cfg['configs'].items():
                if algo not in DEFAULT_SUPPORTED_ALGOS:
                    continue
                cert_chain = []
                if 'cert_chain' in cfg:
                    cert_dir = Path(config_file).parent
                    for fname in cfg['cert_chain']:
                        cert_path = Path(fname)
                        if not cert_path.is_absolute():
                            cert_path = cert_dir / cert_path
                        cert = load_cert_from_pemder(str(cert_path))
                        cert_chain.append(cert)
                        logging.info(
                            "Loaded certificate from %s: %s",
                            cert_path,
                            cert.subject.human_friendly,
                        )
                user_pin = os.environ[cfg['user_pin_env_var']]
                signing_pin_var = cfg.get('signing_pin_env_var', None)
                if signing_pin_var is not None:
                    signing_pin = os.environ[signing_pin_var]
                else:
                    signing_pin = None
                configs[algo] = P11TestConfig(
                    platform=platform,
                    token_label=cfg.get('token_label', None),
                    module=cfg['module'],
                    user_pin=user_pin,
                    cert_label=cfg['cert_label'],
                    key_label=cfg.get('key_label', None),
                    algo=algo,
                    cert_chain_labels=cfg.get('cert_chain_labels', []),
                    cert_chain=cert_chain,
                    freeze_time_spec=cfg.get('freeze_time_spec', None),
                    signing_pin=signing_pin,
                )
            configs['default'] = configs[platform_cfg['default']]
        return configs
    else:
        pkcs11_test_module = os.environ.get('PKCS11_TEST_MODULE', None)
        if not pkcs11_test_module:
            pytest.skip('PKCS11_TEST_MODULE and PKCS11_CONFIG not set')
        configs = {
            k: P11TestConfig(
                platform='softhsm',
                token_label=f"test{k}",
                module=pkcs11_test_module,
                user_pin='1234',
                cert_label='signer1',
                key_label=None,
                algo=k,
                cert_chain_labels=['root', 'interm'],
                cert_chain=[],
                freeze_time_spec='2020-11-01',
                signing_pin=None,
            )
            for k in DEFAULT_SUPPORTED_ALGOS
        }
        configs['default'] = configs['rsa']
        return configs


@pytest.fixture(scope='function')
def p11_config(request, p11_global_test_config, declared_algo, platform):
    from pkcs11 import Attribute, ObjectClass

    try:
        config: P11TestConfig = p11_global_test_config[declared_algo]
    except KeyError:
        pytest.skip(f"No config available for '{declared_algo}'")

    supported_platforms = {
        p
        for mark in request.node.iter_markers(name='hsm')
        for p in mark.kwargs.get('platform', 'all').split(',')
    }
    excluded_platforms = {
        p
        for mark in request.node.iter_markers(name='hsm')
        for p in mark.kwargs.get('exclude', '').split(',')
    }
    if platform in excluded_platforms or (
        supported_platforms
        and platform not in supported_platforms
        and 'all' not in supported_platforms
    ):
        pytest.skip(f"Test is not supported on {platform}")

    if not config.cert_chain:
        certs = []
        with config.session as sess:
            for lbl in config.cert_chain_labels:
                params = {
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.LABEL: lbl,
                }
                try:
                    cert_obj = list(sess.get_objects(params))[0]
                except IndexError:
                    raise RuntimeError(
                        f"Failed to retrieve certificate with label {lbl}"
                    )
                cert = x509.Certificate.load(cert_obj[Attribute.VALUE])
                certs.append(cert)
        config.cert_chain = certs

    if config.freeze_time_spec:
        with freeze_time(config.freeze_time_spec):
            yield config
    else:
        yield config


@pytest.fixture(scope='function')
def p11_session(p11_config):
    from pyhanko.sign import pkcs11

    sess = pkcs11.open_pkcs11_session(
        p11_config.module,
        user_pin=p11_config.user_pin,
        token_criteria=TokenCriteria(label=p11_config.token_label),
    )
    with sess:
        yield sess
