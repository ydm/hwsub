#!/usr/bin/env python

import rsa

from hwsub.device import Device
from hwsub.server import Server


def make_server():
    with open('keys/private.pem', 'rb') as f:
        secret: bytes = f.read()
    return Server(rsa.PrivateKey.load_pkcs1(secret))


def make_device(device_id: int):
    with open('keys/public.pem', 'rb') as f:
        pubkey: bytes = f.read()
    return Device(device_id, rsa.PublicKey.load_pkcs1_openssl_pem(pubkey))


def main():
    server: Server = make_server()
    device: Device = make_device(0x1234)

    def check(prefix: str):
        print('{:21} | check={:>5} time={}'.format(
            prefix, str(device.check()), device.time))

    check('Initially')

    assert device.refresh(server)
    check('After first refresh')

    device.increase_time(1)
    check('After 1s')

    device.increase_time(1)
    check('After 2s')

    device.increase_time(1)
    check('After 3s')

    assert device.refresh(server)
    check('After another refresh')


if __name__ == '__main__':
    main()
