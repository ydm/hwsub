import json
from datetime import timedelta
from random import randint

import rsa
from typing_extensions import Optional

from hwsub.server import Server
from hwsub.types import Request, Response


# LIMIT: float = timedelta(days=7).total_seconds()
LIMIT: float = timedelta(seconds=3).total_seconds()


def random_uint32():
    return randint(0, (1<<0x20) - 1)


class Device:
    '''
    Attributes:
      _time: The total running time (in seconds) since the last
             successful refresh.

    Methods:
      increase_time(): Should be called periodically to track the
                       total running time since the last refresh.
      check(): Returns True if the device is allowed to operate.
      refresh(): Given a server to communicate to, the device checks
                 whether it's allowed to operate and refreshes its
                 state.
    '''

    # Write once memory.
    _device_id: int
    _server_pubkey: rsa.PublicKey

    # Persistent memory.
    _server_nonce: int
    _time: float

    def __init__(self, device_id: int, server_pubkey: rsa.PublicKey):
        self._device_id = device_id
        self._server_pubkey = server_pubkey
        self._server_nonce = 0
        self._time = LIMIT

    def increase_time(self, delta: float) -> None:
        '''
        Should be called periodically.
        '''
        assert delta >= 0
        self._time += delta

    def check(self) -> bool:
        return self._time < LIMIT

    @property
    def time(self) -> float:
        return self._time

    def refresh(self, server: Server) -> bool:
        # 1. Creates a request.
        nonce: int = random_uint32()
        request: Request = Request({
            'device_id': self._device_id,
            'device_nonce': nonce,
        })
        # 2. Sends it to the server.
        response: Optional[Response] = server.handle(request)
        # 3. Inspects server response.
        if response is None:
            return False
        # 4. Inspects the message.
        if response['message']['device_id'] != self._device_id:
            return False
        if response['message']['device_nonce'] != nonce:
            return False
        server_nonce: int = response['message']['server_nonce']
        if server_nonce <= self._server_nonce:
            return False
        # 5. Verify the signature.
        if rsa.verify(
            json.dumps(response['message']).encode(),
            bytes.fromhex(response['signature']),
            self._server_pubkey,
        ) != 'SHA-256':
            return False
        # 6. Everything's good, nullify timer.
        self._server_nonce = server_nonce
        self._time = 0.0
        return True
