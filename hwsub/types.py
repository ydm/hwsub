from typing_extensions import TypedDict


class Request(TypedDict):
    device_id: int
    device_nonce: int


class Message(TypedDict):
    device_id: int
    device_nonce: int
    server_nonce: int    


class Response(TypedDict):
    message: Message
    signature: str
