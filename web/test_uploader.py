import hashlib
import io
import unittest
import zipfile

from web import uploader


class UploadValidation(unittest.TestCase):
    def test_hashes_bytes_and_uses_content_for_format(self):
        payload = b"\x7fELF" + bytes(60)
        record = uploader.inspect_upload(io.BytesIO(payload), "Отчёт.unknown")
        self.assertEqual(record["name"], "Отчёт.unknown")
        self.assertEqual(record["format"], "elf")
        self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())

    def test_rejects_corrupt_declared_zip(self):
        with self.assertRaises(uploader.InputError):
            uploader.inspect_upload(io.BytesIO(b"PK\x03\x04xyz"), "corrupt.zip")

    def test_rejects_zip_traversal_without_extracting(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("../outside.txt", b"test")
        with self.assertRaises(uploader.InputError):
            uploader.inspect_upload(payload, "archive.zip")

    def test_private_service_requires_authentication(self):
        app = uploader.create_app({"APP_PASSWORD": "test-pass", "SESSION_SECRET": "unit-test"})
        response = app.test_client().get("/api/uploads")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
