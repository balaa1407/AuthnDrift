"""
AuthDrift: Authentication Assurance Level Model.

Defines relative authentication assurance tiers aligned with NIST SP 800-63B guidelines.
Ordered numerically (LOW < MEDIUM < HIGH) to enable direct comparison of authentication
method strength across multi-step journeys.

Academic Distinction from NIST SP 800-63B:
In NIST SP 800-63B, Authenticator Assurance Levels (AAL1, AAL2, AAL3) characterize
the overall authentication transaction and process. AuthDrift models the relative
assurance contribution of individual authenticators and mechanisms (LOW < MEDIUM < HIGH)
based on technical properties (e.g., memorized secrets vs. shared-secret out-of-band
tokens vs. phishing-resistant cryptographic keys). A single credential does not
automatically certify an organization at a formal NIST AAL without the complete transaction context.
"""

from enum import IntEnum


class AssuranceLevel(IntEnum):
    """
    Relative assurance levels for authentication methods.

    - LOW (1): Single-factor memorized secrets or legacy fallbacks (e.g., passwords, PINs).
    - MEDIUM (2): Out-of-band or shared-secret multi-factor authenticators (e.g., TOTP, SMS OTP, Email OTP).
    - HIGH (3): Cryptographic hardware-backed or phishing-resistant authenticators
      (e.g., Passkeys, FIDO2/WebAuthn hardware keys, client certificates).
    """
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def from_string(cls, name: str) -> "AssuranceLevel":
        """
        Parses a string into an AssuranceLevel, case-insensitively.
        Defensively defaults to LOW if unrecognized, adhering to fail-closed security.
        """
        if not name:
            return cls.LOW
        normalized = name.strip().upper()
        try:
            return cls[normalized]
        except KeyError:
            return cls.LOW
