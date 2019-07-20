#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 YA-androidapp(https://github.com/YA-androidapp) All rights reserved.
# Required: (on WSL Ubuntu)
#  $ pip install pycrypto

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os


print('AES.BLOCK_SIZE {}'.format(AES.block_size))
DEFAULT_KEY = Random.new().read(AES.block_size)
IV = Random.new().read(AES.block_size)


def get_key(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()


def encrypt(plainfilename, encryptedfilename, key=DEFAULT_KEY):
    chunk_size = 64*1024
    file_size = str(os.path.getsize(plainfilename)).zfill(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    with open(plainfilename, 'rb') as plainfile:
        with open(encryptedfilename, 'wb') as encfile:
            encfile.write(file_size.encode('utf-8'))
            encfile.write(IV)
            while True:
                chunk = plainfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' '.encode('utf-8') * (16 - len(chunk) % 16)
                encfile.write(encryptor.encrypt(chunk))


def decrypt(encryptedfilename, plainfilename, key=DEFAULT_KEY):
    chunk_size = 64*1024
    with open(encryptedfilename, 'rb') as encryptedfile:
        filesize = int(encryptedfile.read(16))
        IV = encryptedfile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(plainfilename, 'wb') as plainfile:
            while True:
                chunk = encryptedfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                plainfile.write(decryptor.decrypt(chunk))
            plainfile.truncate(filesize)


if __name__ == '__main__':
    encrypt('k.mp3', 'encrypted.enc', get_key('test'))
    decrypt('encrypted.enc', 'k2.mp3', get_key('test'))
