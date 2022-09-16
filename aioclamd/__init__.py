import asyncio
import pkg_resources
import re
import struct
from typing import Union, BinaryIO

try:
    __version__ = pkg_resources.get_distribution("aioclamd").version
except:  # noqa
    __version__ = ""
scan_response = re.compile(
    r"^(?P<path>.*): ((?P<virus>.+) )?(?P<status>(FOUND|OK|ERROR))$"
)


class ClamdError(Exception):
    """Base exception for aioclamd"""


class ResponseError(ClamdError):
    """Class for errors when parsing response."""


class BufferTooLongError(ResponseError):
    """
    Class for errors with clamd using INSTREAM with a buffer
    length > StreamMaxLength in /etc/clamav/clamd.conf
    """


class ClamdConnectionError(ClamdError):
    """Class for errors communication with clamd"""


def _parse_response(msg):
    """
    parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
    """
    try:
        return scan_response.match(msg).group("path", "virus", "status")
    except AttributeError:
        raise ResponseError(msg.rsplit("ERROR", 1)[0])


class _AsyncClamdNetworkSocket:
    """This class is a context manager helper to make Clamd calls.

    The socket can be used for only one call,
    so it has to be closed and a new one opened for all requests.
    Use it like this:

    .. code-block::

        async with _AsyncClamdNetworkSocket(host, port) as socket:
            socket.basic_command("PING")

    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
    ):
        """Initialize the _AsyncClamdNetworkSocket

        host (string) : hostname or ip address
        port (int) : TCP port
        """

        self.host = host
        self.port = port

        self.reader: Union[asyncio.StreamReader, None] = None
        self.writer: Union[asyncio.StreamWriter, None] = None

    async def __aenter__(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port
            )
        except Exception as e:
            raise ClamdConnectionError(
                f"Error connecting to {self.host}:{self.port}"
            ) from e
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception as e:  # noqa
            pass

    async def basic_command(self, command):
        """
        Send a command to the clamav server, and return the reply.
        """
        await self.send_command(command)
        response = (await self.recv_response()).rsplit("ERROR", 1)
        if len(response) > 1:
            raise ResponseError(response[0])
        else:
            return response[0]

    async def send_command(self, cmd, *args):
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """
        cmd_to_send = f"n{cmd}{' ' + ' '.join(args) if args else ''}\n".encode("utf-8")
        self.writer.write(cmd_to_send)
        await self.writer.drain()

    async def recv_response(self) -> str:
        """Receive data from clamd"""
        try:
            line = await self.reader.read()
            return line.decode("utf-8").strip()
        except Exception as e:
            raise ClamdConnectionError("Error while reading from socket") from e


class ClamdAsyncClient:
    """
    Class for using clamd through a network socket.
    """

    def __init__(
        self, host: str = "127.0.0.1", port: int = 3310, timeout: float = None
    ):
        """Initialize the AsyncClamdNetworkSocket

        host (string) : hostname or ip address
        port (int) : TCP port
        timeout (float or None) : socket timeout
        """

        self.host = host
        self.port = port
        self.timeout = timeout

    async def instream(self, buffer: BinaryIO) -> dict:
        """Scan a buffer

        buff (filelikeobj): buffer to scan

        return:
          - (dict): ``{filename1: ("virusname", "status")}``

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem

        """
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            await socket.send_command("INSTREAM")

            # MUST be < StreamMaxLength in /etc/clamav/clamd.conf
            chunk_size = 1024
            chunk = buffer.read(chunk_size)
            while chunk:
                size = struct.pack(b"!L", len(chunk))
                socket.writer.write(size + chunk)
                chunk = buffer.read(chunk_size)

            socket.writer.write(struct.pack(b"!L", 0))

            result = await socket.recv_response()

            if len(result) > 0:
                if result == "INSTREAM size limit exceeded. ERROR":
                    raise BufferTooLongError(result)

                filename, reason, status = _parse_response(result)
                return {filename: (status, reason)}

    async def _file_system_scan(self, command, file):
        """Scan a file or directory given by filename using multiple threads
        (faster on SMP machines). Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return:
          - (dict): {filename1: ('FOUND', 'virusname'),
                     filename2: ('ERROR', 'reason')}

        """
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            await socket.send_command(command, file)
            dr = {}
            response = await socket.recv_response()
            for result in response.split("\n"):
                if result:
                    filename, reason, status = _parse_response(result)
                    dr[filename] = (status, reason)

            return dr

    # Convenience methods

    async def ping(self):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("PING")

    async def version(self):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("VERSION")

    async def reload(self):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("RELOAD")

    async def shutdown(self):
        """Force Clamd to shutdown and exit"""
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("SHUTDOWN")

    async def scan(self, file):
        return await self._file_system_scan("SCAN", file)

    async def contscan(self, file):
        return await self._file_system_scan("CONTSCAN", file)

    async def multiscan(self, file):
        return await self._file_system_scan("MULTISCAN", file)
