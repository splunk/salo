#!/usr/bin/env python3

#  Copyright 2021 Splunk Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import random
from typing import List, Optional

from pydantic import Field, validator

from salo import fake

from .base import ZeekModel

TLS_VERSIONS = [
    "TLSv10",
    "TLSv12",
    "TLSv13",
]

TLS_CIPHERS = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
]

TLS_CURVES = ["secp256r1", "secp384r1", "secp521r1", "x25519"]


class SSLModel(ZeekModel):
    _refs: List[str] = [
        "https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info",
        "https://docs.zeek.org/en/master/logs/ssl.html",
    ]
    dest_port: int = Field(default=443)
    version: Optional[str] = None
    cipher: Optional[str] = None
    curve: Optional[str] = None
    server_name: str = Field(default_factory=fake.hostname)
    resumed: Optional[bool] = None
    last_alert: Optional[str] = None
    next_protocol: Optional[str] = None
    established: Optional[bool] = None
    ssl_history: Optional[str] = None
    cert_chain_fps: Optional[List[str]] = None
    client_cert_chain_fps: Optional[List[str]] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    client_subject: Optional[str] = None
    client_issuer: Optional[str] = None
    sni_matches_cert: Optional[bool] = None
    server_version: Optional[int] = None
    client_version: Optional[int] = None
    client_ciphers: Optional[List[int]] = None
    ssl_client_exts: Optional[List[int]] = None
    ssl_server_exts: Optional[List[int]] = None
    ticket_lifetime_hint: Optional[int] = None
    dh_param_size: Optional[int] = None
    point_formats: Optional[List[int]] = None
    client_curves: Optional[List[int]] = None
    orig_alpn: Optional[List[str]] = None
    client_supported_versions: Optional[List[int]] = None
    server_supported_version: Optional[int] = None
    client_key_share_groups: Optional[List[int]] = None
    server_key_share_group: Optional[int] = None
    client_comp_methods: Optional[List[int]] = None
    sigalgs: Optional[List[int]] = None
    hashalgs: Optional[List[int]] = None
    validation_status: Optional[str] = None
    ocsp_status: Optional[str] = None
    valid_ct_logs: Optional[int] = None
    valid_ct_operators: Optional[int] = None
    # TODO: Create a CertNotary::Response class
    # notary: Optional[str] = None
    ja3: str = Field(default_factory=fake.md5)
    ja3s: str = Field(default_factory=fake.md5)

    @validator("dest_port", pre=True, always=True)
    def set_dest_port(cls, v):
        return v or 443

    @validator("version", pre=True, always=True)
    def set_version(cls, v):
        return v or random.choice(TLS_VERSIONS)

    @validator("cipher", pre=True, always=True)
    def set_cipher(cls, v):
        return v or random.choice(TLS_CIPHERS)

    @validator("curve", pre=True, always=True)
    def set_curve(cls, v):
        return v or random.choice(TLS_CURVES)

    @validator("resumed", pre=True, always=True)
    def set_resumed(cls, v):
        return v or fake.boolean(chance_of_getting_true=8)

    @validator("established", pre=True, always=True)
    def set_established(cls, v):
        return v or fake.boolean(chance_of_getting_true=70)
