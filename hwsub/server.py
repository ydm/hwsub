import json

import rsa
from typing_extensions import Dict, Optional

from hwsub.types import Message, Request, Response


def is_subscription_valid(_: int):
    return True


class Server:

    _secret: rsa.PrivateKey
    _nonces: Dict[int, int]

    def __init__(self, secret: rsa.PrivateKey):
        self._secret = secret
        self._nonces = {}

    def handle(self, request: Request) -> Optional[Response]:
        device_id: int = request['device_id']
        device_nonce: int = request['device_nonce']
        if not is_subscription_valid(device_id):
            return None
        self._nonces.setdefault(device_id, 0)
        self._nonces[device_id] += 1
        message = Message({
            'device_id': device_id,
            'device_nonce': device_nonce,
            'server_nonce': self._nonces[device_id],
        })
        signature: bytes = rsa.sign(
            json.dumps(message).encode(),
            self._secret,
            'SHA-256',
        )
        return Response({
            'message': message,
            'signature': signature.hex(),
        })
