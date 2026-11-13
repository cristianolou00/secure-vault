"""
Suite Completa de Testes de Segurança e Funcionalidades (test_vault.py)
"""

import hashlib
import os
import unittest
from vault.storage import VaultStorage
from vault.crypto import (
    derive_key,
    encrypt_bytes,
    decrypt_bytes,
    generate_salt,
    DecryptionError,
)
from vault.secure_mem import SecureBuffer, zero_memory
from vault.models import VaultEntry
from vault.audit import audit_vault
from vault.file_crypto import VaultFileAttachment
from vault.backup import export_entries_to_csv, import_entries_from_csv, change_master_password
from vault.pwned import check_password_leak


class TestSecurityVault(unittest.TestCase):
    TEST_VAULT_PATH = "test_run.vault"

    def tearDown(self):
        for path in (self.TEST_VAULT_PATH, f"{self.TEST_VAULT_PATH}.tmp"):
            if os.path.exists(path):
                os.remove(path)

    def test_memory_zeroing(self):
        raw = bytearray(b"SegredoMuitissimoImportante1234")
        length = len(raw)
        zero_memory(raw)
        self.assertEqual(len(raw), length)
        self.assertTrue(all(b == 0 for b in raw))

    def test_secure_buffer_context_manager(self):
        key_data = b"0123456789ABCDEF0123456789ABCDEF"
        with SecureBuffer(key_data) as sbuf:
            self.assertEqual(sbuf.get_bytes(), key_data)
        self.assertEqual(len(sbuf.data), 0)

    def test_argon2id_and_aesgcm_roundtrip(self):
        pwd = "MinhaPasswordUltraForte!#2026"
        salt = generate_salt()
        plaintext = b"Dados Confidenciais de Teste"
        aad = b"HEADER_AAD_TEST"

        with derive_key(pwd, salt) as key:
            nonce, ciphertext = encrypt_bytes(key, plaintext, associated_data=aad)
            decrypted = decrypt_bytes(key, nonce, ciphertext, associated_data=aad)

        self.assertEqual(decrypted, plaintext)

    def test_wrong_password_rejected(self):
        pwd = "PasswordCorreta"
        wrong_pwd = "PasswordErrada"
        salt = generate_salt()
        plaintext = b"Segredo"

        with derive_key(pwd, salt) as key:
            nonce, ciphertext = encrypt_bytes(key, plaintext)

        with derive_key(wrong_pwd, salt) as wrong_key:
            with self.assertRaises(DecryptionError):
                decrypt_bytes(wrong_key, nonce, ciphertext)

    def test_security_audit_engine(self):
        e1 = VaultEntry(title="S1", username="u1", password="123")  # Fraca
        e2 = VaultEntry(title="S2", username="u2", password="123")  # Fraca e repetida
        e3 = VaultEntry(title="S3", username="u3", password="K9#mQ!8zL$p2@Wv9&Yx")  # Forte e única

        report = audit_vault([e1, e2, e3])
        self.assertEqual(report.total_entries, 3)
        self.assertEqual(report.total_weak, 2)
        self.assertEqual(report.total_reused, 2)
        self.assertLess(report.health_score, 80)

    def test_file_attachment_serialization(self):
        sample_bytes = b"%PDF-1.4 Documento ultraconfidencial de teste"
        attachment = VaultFileAttachment(filename="contrato.pdf", data_bytes=sample_bytes)
        d = attachment.to_dict()
        reconstructed = VaultFileAttachment.from_dict(d)
        self.assertEqual(reconstructed.filename, "contrato.pdf")
        self.assertEqual(reconstructed.data_bytes, sample_bytes)

    def test_csv_export_and_import(self):
        e1 = VaultEntry(title="GitHub", username="dev", password="SuperPassword!123", url="https://github.com")
        csv_str = export_entries_to_csv([e1])
        imported, count = import_entries_from_csv(csv_str)
        self.assertEqual(count, 1)
        self.assertEqual(imported[0].title, "GitHub")
        self.assertEqual(imported[0].password, "SuperPassword!123")

    def test_change_master_password(self):
        old_pwd = "OldMasterPassword123!"
        new_pwd = "NewMasterPassword456!"
        data = {"vault_name": "Teste", "version": 1, "entries": {"1": {"id": "1", "title": "Conta", "username": "u", "password": "p", "url": "", "notes": "", "category": "G", "created_at": "", "updated_at": ""}}, "files": {}}

        VaultStorage.create_new_vault(self.TEST_VAULT_PATH, old_pwd, data)
        change_master_password(self.TEST_VAULT_PATH, old_pwd, new_pwd)

        with self.assertRaises(DecryptionError):
            VaultStorage.load_vault(self.TEST_VAULT_PATH, old_pwd)

        loaded = VaultStorage.load_vault(self.TEST_VAULT_PATH, new_pwd)
        self.assertEqual(loaded["vault_name"], "Teste")

    def test_k_anonymity_sha1_hashing(self):
        """Valida se o cálculo de SHA-1 e partição de prefixo/sufixo para k-Anonymity está matematicamente correto."""
        test_pwd = "password123"
        expected_full_sha1 = "CBFDAC6008F9CAB4083784CBD1874F76618D2A97"
        computed_sha1 = hashlib.sha1(test_pwd.encode("utf-8")).hexdigest().upper()
        self.assertEqual(computed_sha1, expected_full_sha1)
        prefix = computed_sha1[:5]
        suffix = computed_sha1[5:]
        self.assertEqual(prefix, "CBFDA")
        self.assertEqual(len(suffix), 35)


if __name__ == "__main__":
    unittest.main()
