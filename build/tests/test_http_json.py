from __future__ import annotations

import pytest

from chainlog.http_json import ResponseBodyTooLargeError, bounded_response_json


class FakeStreamingResponse:
    def __init__(self, chunks: list[bytes], headers: dict[str, str] | None = None):
        self._chunks = chunks
        self.headers = headers or {}
        self.iterated = False

    def iter_bytes(self):
        self.iterated = True
        yield from self._chunks


def test_bounded_json_decodes_valid_payload():
    response = FakeStreamingResponse([b'{"events":', b'[]}', b''])
    assert bounded_response_json(response, max_bytes=64) == {"events": []}


def test_bounded_json_rejects_content_length_before_reading_body():
    response = FakeStreamingResponse([b"{}"], headers={"Content-Length": "1025"})
    with pytest.raises(ResponseBodyTooLargeError):
        bounded_response_json(response, max_bytes=1024)
    assert response.iterated is False


def test_bounded_json_rejects_streamed_body_over_limit():
    response = FakeStreamingResponse([b"1234", b"5678"])
    with pytest.raises(ResponseBodyTooLargeError):
        bounded_response_json(response, max_bytes=7)


def test_bounded_json_rejects_invalid_json():
    with pytest.raises(ValueError, match="JSON UTF-8"):
        bounded_response_json(FakeStreamingResponse([b"{broken"]), max_bytes=64)
