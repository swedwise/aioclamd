import base64
import pathlib
from io import BytesIO

import pytest

from aioclamd import ClamdAsyncClient

pytest_plugins = ("pytest_asyncio",)


@pytest.fixture()
def eicar():
    yield BytesIO(
        base64.b64decode(
            b"WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNU"
            b"QU5EQVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n"
        )
    )


@pytest.mark.asyncio
async def test_ping():
    clamd = ClamdAsyncClient()
    assert await clamd.ping() == "PONG"


@pytest.mark.asyncio
async def test_version():
    clamd = ClamdAsyncClient()
    assert (await clamd.version()).startswith("ClamAV")


@pytest.mark.asyncio
async def test_scan_filesystem():
    clamd = ClamdAsyncClient()
    assert (await clamd.scan("/etc/clamav/clamd.conf")).get(
        "/etc/clamav/clamd.conf"
    ) == ("OK", None)


@pytest.mark.asyncio
async def test_contscan_filesystem():
    clamd = ClamdAsyncClient()
    assert len(await clamd.scan("/etc/")) == 4


@pytest.mark.asyncio
async def test_multiscan_filesystem():
    clamd = ClamdAsyncClient()
    assert len(await clamd.multiscan("/etc/")) == 4


@pytest.mark.asyncio
async def test_instream_eicar(eicar):
    clamd = ClamdAsyncClient()
    assert await clamd.instream(eicar) == {"stream": ("FOUND", "Win.Test.EICAR_HDB-1")}


@pytest.mark.asyncio
async def test_instream_this_file():
    clamd = ClamdAsyncClient()
    assert await clamd.instream(BytesIO(pathlib.Path(__file__).read_bytes())) == {
        "stream": ("OK", None)
    }
