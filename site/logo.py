# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

SIGNATURE = b"\x89PNG\r\n\x1a\n"
CHANNELS = {2: 3, 6: 4}


@dataclass
class Image:
    width: int
    height: int
    channels: int
    rows: list[bytearray]


def chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(SIGNATURE):
        raise ValueError("not a PNG file")
    found = []
    position = len(SIGNATURE)
    while position < len(data):
        (length,) = struct.unpack(">I", data[position:position + 4])
        kind = data[position + 4:position + 8]
        found.append((kind, data[position + 8:position + 8 + length]))
        position += 12 + length
    return found


def paeth(left: int, up: int, corner: int) -> int:
    estimate = left + up - corner
    distance_left = abs(estimate - left)
    distance_up = abs(estimate - up)
    distance_corner = abs(estimate - corner)
    if distance_left <= distance_up and distance_left <= distance_corner:
        return left
    return up if distance_up <= distance_corner else corner


def unfilter(kind: int, line: bytearray, previous: bytearray, step: int) -> bytearray:
    if kind == 1:
        for index in range(step, len(line)):
            line[index] = (line[index] + line[index - step]) & 0xFF
    elif kind == 2:
        line = bytearray((value + above) & 0xFF for value, above in zip(line, previous))
    elif kind == 3:
        for index in range(len(line)):
            left = line[index - step] if index >= step else 0
            line[index] = (line[index] + ((left + previous[index]) >> 1)) & 0xFF
    elif kind == 4:
        for index in range(len(line)):
            left = line[index - step] if index >= step else 0
            corner = previous[index - step] if index >= step else 0
            line[index] = (line[index] + paeth(left, previous[index], corner)) & 0xFF
    elif kind != 0:
        raise ValueError(f"unknown PNG filter {kind}")
    return line


def read(path: Path) -> Image:
    header = b""
    compressed = bytearray()
    for kind, body in chunks(path.read_bytes()):
        if kind == b"IHDR":
            header = body
        elif kind == b"IDAT":
            compressed += body
    width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", header)
    if depth != 8 or colour not in CHANNELS or interlace != 0:
        raise ValueError(f"{path}: only 8-bit, non-interlaced RGB or RGBA PNG is supported")
    channels = CHANNELS[colour]
    stride = width * channels
    raw = zlib.decompress(bytes(compressed))
    rows: list[bytearray] = []
    previous = bytearray(stride)
    for row in range(height):
        start = row * (stride + 1)
        line = unfilter(raw[start], bytearray(raw[start + 1:start + 1 + stride]), previous, channels)
        rows.append(line)
        previous = line
    return Image(width, height, channels, rows)


def crop(image: Image, left: int, top: int, size: int) -> Image:
    step = image.channels
    rows = [bytearray(line[left * step:(left + size) * step]) for line in image.rows[top:top + size]]
    return Image(size, size, step, rows)


def shrink(image: Image, factor: int) -> Image:
    step = image.channels
    width = image.width // factor
    height = image.height // factor
    area = factor * factor
    rows = []
    for row in range(height):
        sums = [0] * (image.width * step)
        for line in image.rows[row * factor:(row + 1) * factor]:
            sums = [total + value for total, value in zip(sums, line)]
        out = bytearray(width * step)
        for column in range(width):
            for channel in range(step):
                start = column * factor * step + channel
                out[column * step + channel] = sum(sums[start:start + factor * step:step]) // area
        rows.append(out)
    return Image(width, height, step, rows)


def resize(image: Image, size: int) -> Image:
    step = image.channels
    rows = []
    for row in range(size):
        top = row * image.height // size
        bottom = max(top + 1, (row + 1) * image.height // size)
        out = bytearray(size * step)
        for column in range(size):
            left = column * image.width // size
            right = max(left + 1, (column + 1) * image.width // size)
            count = (bottom - top) * (right - left)
            for channel in range(step):
                total = 0
                for line in image.rows[top:bottom]:
                    total += sum(line[left * step + channel:right * step:step])
                out[column * step + channel] = total // count
        rows.append(out)
    return Image(size, size, step, rows)


def filtered(image: Image) -> bytes:
    step = image.channels
    previous = bytearray(image.width * step)
    out = bytearray()
    for line in image.rows:
        out.append(4)
        for index, value in enumerate(line):
            left = line[index - step] if index >= step else 0
            corner = previous[index - step] if index >= step else 0
            out.append((value - paeth(left, previous[index], corner)) & 0xFF)
        previous = line
    return bytes(out)


def chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def write(image: Image, path: Path) -> None:
    colour = 2 if image.channels == 3 else 6
    header = struct.pack(">IIBBBBB", image.width, image.height, 8, colour, 0, 0, 0)
    data = SIGNATURE + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(filtered(image), 9)) + chunk(b"IEND", b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
