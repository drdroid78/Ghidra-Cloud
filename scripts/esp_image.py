"""Validate Espressif image boundaries and wrap mapped segments in a static ELF."""

import hashlib
import struct
from functools import reduce
from operator import xor

# Image layout: Espressif esptool firmware-image-format documentation.
# Executable mappings: esptool targets esp32, esp32s3, esp32c3 (v5.2.0).
CHIPS = {
    0: ("ESP32", 94, ((0x40080000, 0x400A0000), (0x400D0000, 0x40400000)), (0x3F400000, 0x3F800000)),
    5: ("ESP32-C3", 243, ((0x4037C000, 0x403E0000), (0x42000000, 0x42800000), (0x50000000, 0x50002000)), (0x3C000000, 0x3C800000)),
    9: ("ESP32-S3", 94, ((0x40370000, 0x403E0000), (0x42000000, 0x44000000)), (0x3C000000, 0x3E000000)),
}
MAX_IMAGE = 32 * 1024 * 1024


def parse(stream, start, file_size):
    stream.seek(start)
    header = stream.read(24)
    if len(header) != 24 or header[0] != 0xE9 or not 1 <= header[1] <= 16 or header[23] not in (0, 1):
        return None
    if header[19:23] != bytes(4):
        return None
    entry = struct.unpack_from("<I", header, 4)[0]
    chip_id = struct.unpack_from("<H", header, 12)[0]
    name, machine, executable_ranges, drom = CHIPS.get(chip_id, ("unknown", None, (), (0, 0)))
    if entry == 0:
        return None
    segments = []
    checksum = 0xEF
    digest = hashlib.sha256(header)
    for index in range(header[1]):
        segment_header = stream.read(8)
        if len(segment_header) != 8:
            return None
        address, size = struct.unpack("<II", segment_header)
        offset = stream.tell()
        if not size or offset + size > min(file_size, start + MAX_IMAGE) or address + size > 1 << 32:
            return None
        digest.update(segment_header)
        remaining = size
        while remaining:
            block = stream.read(min(remaining, 256 * 1024))
            if not block:
                return None
            checksum = reduce(xor, block, checksum)
            digest.update(block)
            remaining -= len(block)
        executable = address <= entry < address + size or any(lo <= address and address + size <= hi
                                                               for lo, hi in executable_ranges)
        writable = not executable and not (drom[0] <= address and address + size <= drom[1])
        segments.append({"index": index, "offset": offset, "address": address, "size": size,
                         "executable": executable, "writable": writable})
    padding = stream.read((15 - (stream.tell() - start)) % 16)
    recorded_checksum = stream.read(1)
    if recorded_checksum != bytes([checksum]):
        return None
    digest.update(padding + recorded_checksum)
    if header[23] and stream.read(32) != digest.digest():
        return None
    mapped = sorted((segment for segment in segments if segment["address"] >= 0x10000), key=lambda s: s["address"])
    overlap = any(a["address"] + a["size"] > b["address"] for a, b in zip(mapped, mapped[1:]))
    eligible = machine is not None and not overlap and any(s["address"] <= entry < s["address"] + s["size"] for s in mapped)
    return {"offset": start, "length": stream.tell() - start, "chip_id": chip_id, "chip": name,
            "machine": machine, "entry": entry, "segments": segments, "elf_supported": eligible}


def images(stream):
    stream.seek(0, 2)
    size = stream.tell()
    offsets = {0, 0x1000, 0x10000}
    # Standard partition table. Only application offsets are considered.
    stream.seek(0x8000)
    for _ in range(95):
        row = stream.read(32)
        if len(row) != 32 or row[:2] != b"\xaa\x50":
            break
        partition_offset = struct.unpack_from("<I", row, 4)[0]
        if row[2] == 0 and partition_offset % 0x1000 == 0 and 0 < partition_offset < size:
            offsets.add(partition_offset)
            if len(offsets) >= 11:
                break
    return [parsed for offset in sorted(offsets) if offset + 24 <= size and (parsed := parse(stream, offset, size))]


def write_elf(source, image, output):
    if not image["elf_supported"]:
        raise ValueError("The ESP architecture or memory map could not be determined confidently")
    segments = [segment for segment in image["segments"] if segment["address"] >= 0x10000]
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    position = 52 + 32 * len(segments)
    names = bytearray(b"\0")
    program_headers = []
    sections = [bytes(40)]
    for segment in segments:
        address = segment["address"]
        size = segment["size"]
        executable = segment["executable"]
        writable = segment["writable"]
        name_offset = len(names)
        prefix = ".text." if executable else ".data." if writable else ".rodata."
        names.extend(prefix.encode() + str(segment["index"]).encode() + b"\0")
        program_flags = 4 | int(executable) | (int(writable) << 1)
        section_flags = 2 | (int(executable) << 2) | int(writable)
        program_headers.append(struct.pack("<8I", 1, position, address, address, size, size, program_flags, 1))
        sections.append(struct.pack("<10I", name_offset, 1, section_flags, address, position, size, 0, 0, 1, 0))
        position += size
    name_offset = len(names)
    names.extend(b".shstrtab\0")
    sections.append(struct.pack("<10I", name_offset, 3, 0, 0, position, len(names), 0, 0, 1, 0))
    section_offset = position + len(names)
    output.write(struct.pack("<16sHHIIIIIHHHHHH", ident, 2, image["machine"], 1, image["entry"], 52,
                             section_offset, 1 if image["machine"] == 243 else 0, 52, 32, len(program_headers),
                             40, len(sections), len(sections) - 1))
    output.write(b"".join(program_headers))
    for segment in segments:
        source.seek(segment["offset"])
        remaining = segment["size"]
        while remaining:
            block = source.read(min(remaining, 256 * 1024))
            if not block:
                raise ValueError("Truncated ESP segment")
            output.write(block)
            remaining -= len(block)
    output.write(names)
    output.write(b"".join(sections))
