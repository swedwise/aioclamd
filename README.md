# aioclamd

[![aioclamd](https://img.shields.io/pypi/v/aioclamd.svg)](https://pypi.python.org/pypi/aioclamd)
[![Build and Test](https://github.com/swedwise/aioclamd/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/swedwise/aioclamd/actions/workflows/build_and_test.yml)
[![Format and Lint](https://github.com/swedwise/aioclamd/actions/workflows/format_and_lint.yml/badge.svg)](https://github.com/swedwise/aioclamd/actions/workflows/format_and_lint.yml)
[![Publish to pypi.org](https://github.com/swedwise/aioclamd/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/swedwise/aioclamd/actions/workflows/pypi-publish.yml)
[![Publish to test.pypi.org](https://github.com/swedwise/aioclamd/actions/workflows/test-pypi-publish.yml/badge.svg)](https://github.com/swedwise/aioclamd/actions/workflows/test-pypi-publish.yml)


This package is an asynchronous version of the pleasant package 
[`python-clamd`](https://github.com/graingert/python-clamd). It has the same external
API, only all methods are coroutines and all communication is handled 
asynchronously using the ``asyncio`` framework.

The `ClamdAsyncClient` connects to a [ClamAV](https://www.clamav.net/) antivirus instance and scans
files and data for malicious threats. This package does not bundle ClamAV in any way,
so a running instance of the `clamd` deamon is required.

## Installation

```
pip install aioclamd
```

## Usage

To scan a file (on the system where ClamAV is installed):

```python
import asyncio

from aioclamd import ClamdAsyncClient

async def main(host, port):
    clamd = ClamdAsyncClient(host, port)
    print(await clamd.scan('/etc/clamav/clamd.conf'))

asyncio.run(main("127.0.0.1", 3310))

# Output:
# {'/etc/clamav/clamd.conf': ('OK', None)}
```

To scan a data stream:

```python
import asyncio
import base64
from io import BytesIO

from aioclamd import ClamdAsyncClient

EICAR = BytesIO(
    base64.b64decode(
        b"WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNU"
        b"QU5EQVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n"
    )
)

async def main(host, port):
    clamd = ClamdAsyncClient(host, port)
    print(await clamd.instream(EICAR))

asyncio.run(main("127.0.0.1", 3310))

# Output:
# {'stream': ('FOUND', 'Win.Test.EICAR_HDB-1')}
```

## Development

A local instance of  [ClamAV](https://www.clamav.net/) can be had with Docker:

```powershell
docker run -p 3310:3310 --rm clamav/clamav
```
