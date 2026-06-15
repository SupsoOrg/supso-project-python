"""Trusted issuer keys — Supso's production anchor, baked into the published
package so a downstream user cannot substitute their own.

Each scheme is a list so a key can be rotated (ship a release with old + new,
re-issue, then drop the old entry). Mirrors the Rust crate's ``keys.rs`` and the
TypeScript package's ``keys.ts``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import SupsoError

#: Supso's production Ed25519 public keys, 64-char lowercase hex (32 bytes).
TRUSTED_ED25519_KEYS_HEX: tuple[str, ...] = (
    "b1ef6d78434daaf5dae5e3df7996a3edc155198c71c92b91f539ce2fe649e9d4",
)

#: Supso's production ML-DSA-44 public keys, 2624-char lowercase hex (1312 bytes).
TRUSTED_MLDSA44_KEYS_HEX: tuple[str, ...] = (
    "1be0e29d77a9998bb7661228a79e1d8118aa9ad88535720563d1aef9b8abc0d3d037cd984f3f652fc5512c935593dcd9f470540e125f0e9bcdc17c0bad721386bb3e3cd28cf895cbd0168cfcaee5131e581e2916abc7a1c25022f016c81781d16cd8b4cd8c36a7ced2a1753e4c01f69a05e9acb6f1926867a028f0a5ae6c1f22873c3df3d562f2ec844d422c8c68b2deba9257a13013bd009a227d7c40a3aa81129b6ed1f950a0cf75f3cfb9fc0e405d7fc929ecc9bf59dc566b075b3b80ad914fd150749b9022638e99a7d64b68ff82e295609dc2f6bd291463c417a1e69e7e145164fb3787c5bc90fe1dc4268bbd4d4e44c13d50120cf161466fbb53ea2a5f724ace3afef42eeeb0d631ad2b815b5442caddb509ed9d1cc8ab79ba4042fa168245d1446294677503eed33410a979a0646da3393e7c2a6e450c63c55ecc5bd92771ef7b278b3cef2d80fa306733fb2ecee4b2f4bb07c3b14ad29da4607b97e04cfefb76258000185c6d795ff91e9af4a0acf54a25ddbf14814540461474d67d6b9503d7e07e97907ef483593f97b9d039c4e548b25917d722c1c3e5ae7f81a1c232faf5a6978641230408cc01d70724f64e150836388dcadf60ae5be134ab5413228e5ab13402aa4331d144b586e1cb05d7a4034a9a5f71513d6029615197212b4a68684d05fedfe92bb05f24eccb6a9be9c1fa1003ba106718db9d39d4a08c5b6ae014d0086a957ed033e74af13d9a94d549524316d6aa544487eab716878a4a07ca3285724af050fccc8c3f8c3c82e2cd271133ca9562e71238e23baca5ec297ff50ebee8b2461607054d8f18d60b012b6eee2240adfa38b05f10ca679c271922907819974b5481d0aa7cab37c215123a6b6d7067856dfc475a8c2e3e54b658deb0709c8cb77b0a8508519d44b784f7584966d978d65b78e11e059c1e4b5441fd1625af92b2d647c5f0805343243b2225882b3c9beda4c1102aff1c084dac105da2d37813881fad33a860cc655bb45fac59d73ac2d92fb4fde59cbf10bdd07541e605d008467ea4c20e0c2796683499b19adb394dea4c8260c7438fb9efe2db2d65b9f7f4f2a8068a1010f70b7b2ae83c92dac6af023fe7f41eccba36d702b1bd73c88147f3ebc4f9e5416573321567b224a255e3edaf6afce2bce7b1d33955bb3288bf1da61709488c84e9321385e6ac71d120b752698f60eed6f1e75b12c04b30f998450cedecf91c6e611e7f23d5ca1252f89b699196f726931078f7e93d5a81b32613f7fe42563b907dae17822757bd66a0b1d3aecce3b5a01d317f085322c2df01cea971b0e3b58ec7cd80d681dafbc6ed2eeadcef36e8168336aa8954fd1cf6426702679d8e3f57a8e0b9cda12dd0ccf0aeb5a6f84ac5e2e0d4e43093063f1b8e1103359bc92d5a1891d8e34ec44a97469941d5b2665c5cfb910019840a8b8efd7e59e3bb727dbd09d3d68cf9b4f4c42687b762da645233bfb55b5fa523eca0241e4a6649e12aa41b5d52a2a6cdd043e1bcd500c6c99ba7fe33bd39a5f380be88c14ebaf01c24034b4b57b04a290336240ee06c0feaa495aee10f15006cff5750061bc93091660dd945efda00ddbd50cff8f69b85c18493ae21f70e1d9b29c6b90457177f9313764d505738b5474550b1e6969fac1aac7a3f25b6bef5d0be43eab4b464a8a86be08417935a8f5d097cc237a0f57e4330c18ef54d376e42a2b8d17a1c3e18a6a84c123cff67ea4f2e86284a34862f81c0c65cf79cb5c972de88a98e5c0ce89530739729610b39ac1f03f5158e26b81e364219ead057d43b222bbd93c39d3507c127ca78a7c6a85511ba92195b125f8ff70cb2d5c7b2",
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_ED25519_KEY_LEN = 32
_MLDSA44_KEY_LEN = 1312


@dataclass(frozen=True)
class IssuerKeys:
    """A set of trusted issuer verifying keys, one list per scheme.

    A token is accepted iff its signature verifies under **at least one** key in
    each list (SPEC §4 "Key rotation").
    """

    #: Parsed Ed25519 public keys.
    ed25519: tuple[Ed25519PublicKey, ...]
    #: Raw ML-DSA-44 public-key bytes (1312 each), passed to the verifier as-is.
    mldsa44: tuple[bytes, ...]

    @classmethod
    def from_hex(
        cls,
        ed25519_hex: "list[str] | tuple[str, ...]",
        mldsa44_hex: "list[str] | tuple[str, ...]",
    ) -> "IssuerKeys":
        """Build a trust anchor from hex key lists (self-hosting issuers and tests)."""
        ed = tuple(
            Ed25519PublicKey.from_public_bytes(_decode_key(h, _ED25519_KEY_LEN, "Ed25519"))
            for h in ed25519_hex
        )
        pq = tuple(_decode_key(h, _MLDSA44_KEY_LEN, "ML-DSA-44") for h in mldsa44_hex)
        return cls(ed25519=ed, mldsa44=pq)

    @classmethod
    def supso(cls) -> "IssuerKeys":
        """The baked-in Supso production anchor."""
        return cls.from_hex(TRUSTED_ED25519_KEYS_HEX, TRUSTED_MLDSA44_KEYS_HEX)


def _decode_key(hex_str: str, byte_len: int, scheme: str) -> bytes:
    if len(hex_str) != byte_len * 2 or not _HEX_RE.match(hex_str):
        raise SupsoError("bad_trusted_key", f"{scheme} key hex is malformed")
    return bytes.fromhex(hex_str)
