"""HTTP wire-codec helpers — extracted verbatim from core/client.py.

Pure content-decode helpers used by the raw-socket transport paths.
"""


def _dechunk(data: bytes) -> bytes:
    """Decode HTTP/1.1 chunked transfer-encoding framing (raw-socket path)."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        j = data.find(b"\r\n", i)
        if j == -1:
            return bytes(data)  # malformed framing — hand back untouched
        try:
            size = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(data)
        if size == 0:
            break
        start = j + 2
        out += data[start:start + size]
        i = start + size + 2  # skip chunk data + trailing CRLF
    return bytes(out)
