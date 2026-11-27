import hashlib
import io
import struct
import tempfile
import unittest
import zipfile

from web import uploader
from scripts import esp_image


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

    def test_limit_rejects_file_one_byte_over_100_mib(self):
        with tempfile.TemporaryFile() as stream:
            stream.truncate(100 * 1024 * 1024 + 1)
            with self.assertRaises(uploader.InputError):
                uploader.inspect_upload(stream, "over-limit.bin")

    def test_espressif_keeps_separate_virtual_segments(self):
        image = bytearray(struct.pack("<BBBBI", 0xE9, 2, 0, 0, 0x40380000) + bytes(16))
        struct.pack_into("<H", image, 12, 5)
        image.extend(struct.pack("<II", 0x40380000, 4) + b"\x67\x80\x00\x00")
        image.extend(struct.pack("<II", 0x3C000020, 4) + b"data")
        check = 0xef ^ 0x67 ^ 0x80 ^ ord("d") ^ ord("a") ^ ord("t") ^ ord("a")
        image.extend(bytes((15 - len(image)) % 16) + bytes([check]))
        stream = io.BytesIO(image)
        info = esp_image.images(stream)[0]
        converted = io.BytesIO()
        esp_image.write_elf(stream, info, converted)
        data = converted.getvalue()
        self.assertEqual(struct.unpack_from("<H", data, 18)[0], 243)
        self.assertEqual(struct.unpack_from("<I", data, 24)[0], 0x40380000)
        headers = [struct.unpack_from("<8I", data, 52 + i * 32) for i in range(2)]
        self.assertEqual([header[2] for header in headers], [0x40380000, 0x3C000020])
        self.assertEqual([header[6] for header in headers], [5, 4])
        stream.getbuffer()[-1] ^= 1
        self.assertEqual(esp_image.images(stream), [])


if __name__ == "__main__":
    unittest.main()
