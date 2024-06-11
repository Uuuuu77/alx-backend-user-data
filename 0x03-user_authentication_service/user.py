#!/usr/bin/env python3

""" User model """

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from typing import Optional

Base = declarative_base()


class User(Base):
    """ User class """
    __tablename__: str = 'users'

    id: int = Column(Integer, primary_key=True)
    email: str = Column(String(250), nullable=False)
    hashed_password: str = Column(String(250), nullable=False)
    session_id: Optional[str] = Column(String(250), nullable=True)
    reset_token: Optional[str] = Column(String(250), nullable=True)
