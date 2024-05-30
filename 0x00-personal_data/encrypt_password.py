#!/usr/bin/env python3

""" Encrypting and Check valid passwords """

import bcrypt


def hash_password(password: str) -> bytes:
    """ Hashing a password using bcrypt """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Checks if the password is valid """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
