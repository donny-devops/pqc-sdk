from __future__ import annotations

from typing import TypedDict


class KEMParams(TypedDict):
    pk_size: int
    sk_size: int
    ct_size: int
    ss_size: int
    security_level: int
    oqs_name: str


class DSAParams(TypedDict):
    pk_size: int
    sk_size: int
    sig_size: int
    security_level: int
    oqs_name: str
    fips: str
