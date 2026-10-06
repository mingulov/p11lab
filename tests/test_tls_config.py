"""Per-run proxy TLS generation and refusal contracts."""
import os
from pathlib import Path
import stat

import pytest

from p11lab import tls


@pytest.fixture
def material(tmp_path):
    return tls.create_test_tls(tmp_path / 'tls', ('provider-daemon', 'localhost', '127.0.0.1'))


def test_generated_leaves_carry_verified_san_and_eku(material):
    assert material['server_names'] == ['provider-daemon', 'localhost', '127.0.0.1']
    assert material['evidence']['server']['sans'] == ['127.0.0.1', 'localhost', 'provider-daemon']
    assert material['evidence']['server']['chain'].endswith('OK')
    assert material['evidence']['client']['chain'].endswith('OK')
    assert 'p11lab-client' in material['evidence']['client']['subject']
    assert material['openssl_version'].startswith('OpenSSL ')
    for key in ('ca_key', 'server_key', 'client_key'):
        assert stat.S_IMODE(os.stat(material[key]).st_mode) == 0o600
    for cert in ('ca_cert', 'server_cert', 'client_cert'):
        assert stat.S_IMODE(os.stat(material[cert]).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(material['dir']).st_mode) == 0o700


def test_mount_sets_never_contain_ca_private_key(material):
    assert set(tls.daemon_mount_files(material)) == {'ca_cert', 'server_cert', 'server_key'}
    assert set(tls.consumer_mount_files(material)) == {'ca_cert', 'client_cert', 'client_key'}
    assert material['ca_key'] not in tls.daemon_mount_files(material).values()
    assert material['ca_key'] not in tls.consumer_mount_files(material).values()


def test_wrong_hostname_fails_server_verification(material, tmp_path):
    with pytest.raises(ValueError, match='SAN does not cover'):
        tls.verify_server_identity(server_cert=Path(material['server_cert']),
                                   ca_cert=Path(material['ca_cert']),
                                   expected_names=('someone-else',))


def test_foreign_ca_fails_chain_verification(material, tmp_path):
    other = tls.create_test_tls(tmp_path / 'other', ('provider-daemon',))
    with pytest.raises(ValueError, match='chain verification failed'):
        tls.verify_server_identity(server_cert=Path(material['server_cert']),
                                   ca_cert=Path(other['ca_cert']),
                                   expected_names=('provider-daemon',))
    with pytest.raises(ValueError, match='chain verification failed'):
        tls.verify_client_identity(client_cert=Path(material['client_cert']),
                                   ca_cert=Path(other['ca_cert']))


def test_partial_tls_triple_is_refused():
    with pytest.raises(ValueError, match='partial TLS configuration'):
        tls.split_tls_env({'PKCS11_PROXY_TLS_CA_CERT': '/ca.crt',
                           'PKCS11_PROXY_TLS_CLIENT_CERT': '/client.crt'})
    assert tls.split_tls_env({}) == {}


def test_consumer_env_requires_https_and_complete_paths():
    with pytest.raises(ValueError):
        tls.build_consumer_env(endpoint='http://provider-daemon:7512', ca_cert='/ca',
                               client_cert='/crt', client_key='/key')
    with pytest.raises(ValueError):
        tls.build_consumer_env(endpoint='https://provider-daemon:7512', ca_cert='/ca',
                               client_cert='', client_key='/key')
    env = tls.build_consumer_env(endpoint='https://provider-daemon:7512', ca_cert='/ca',
                                 client_cert='/crt', client_key='/key')
    assert env['PKCS11_PROXY_ENDPOINT'] == 'https://provider-daemon:7512'


def test_group_readable_private_key_is_refused(material):
    key = Path(material['client_key'])
    key.chmod(0o640)
    with pytest.raises(ValueError, match='no group/other permissions'):
        tls.check_tls_file_permissions({'client_key': key}, owner_uid=os.geteuid())


def test_world_writable_certificate_is_refused(material):
    cert = Path(material['client_cert'])
    cert.chmod(0o666)
    with pytest.raises(ValueError, match='not be world-writable'):
        tls.check_tls_file_permissions({'client_cert': cert}, owner_uid=os.geteuid())


def test_wrong_owner_is_refused(material):
    with pytest.raises(ValueError, match='ownership mismatch'):
        tls.check_tls_file_permissions({'client_key': Path(material['client_key'])},
                                       owner_uid=os.geteuid() + 1)


def test_missing_tls_file_is_refused(tmp_path):
    with pytest.raises(ValueError, match='missing'):
        tls.check_tls_file_permissions({'client_key': tmp_path / 'absent.key'},
                                       owner_uid=os.geteuid())


def test_existing_output_directory_is_refused(tmp_path):
    tmp_path.joinpath('taken').mkdir()
    with pytest.raises(ValueError, match='fresh'):
        tls.create_test_tls(tmp_path / 'taken', ('provider-daemon',))


def test_invalid_server_names_are_refused(tmp_path):
    for names in ((), ('',), ('bad name!',), ('x' * 300,)):
        with pytest.raises(ValueError):
            tls.create_test_tls(tmp_path / ('tls-' + str(len(str(names)))), names)
