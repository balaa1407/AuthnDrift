"""
AuthDrift: Relative Authentication Assurance Model.

Defines relative authenticator assurance tiers and academic justifications
aligned with NIST SP 800-63B (Digital Identity Guidelines: Authentication
and Lifecycle Management).

Note on NIST SP 800-63B alignment:
In NIST SP 800-63B, Authenticator Assurance Levels (AAL1, AAL2, AAL3) characterize
the overall authentication transaction and process. AuthDrift models the relative
assurance contribution of individual authenticators and mechanisms (LOW < MEDIUM < HIGH)
based on NIST SP 800-63B authenticator requirements (e.g., memorized secrets vs.
out-of-band/shared secrets vs. phishing-resistant cryptographic hardware authenticators).
"""

from typing import Dict, Optional, Tuple
from backend.models.assurance import AssuranceLevel


class AssuranceModel:
    """
    Configurable relative authentication assurance model.

    Maps authentication method identifiers to relative AssuranceLevel tiers
    and provides clear rationale for every classification based on NIST SP 800-63B.
    """

    def __init__(self, custom_mapping: Optional[Dict[str, AssuranceLevel]] = None):
        # Default baseline mapping aligned with NIST SP 800-63B
        self._mapping: Dict[str, AssuranceLevel] = {
            # High Assurance (Phishing-resistant / Hardware cryptographic)
            "passkey": AssuranceLevel.HIGH,
            "fido2": AssuranceLevel.HIGH,
            "webauthn": AssuranceLevel.HIGH,
            "hardware_token": AssuranceLevel.HIGH,
            "u2f": AssuranceLevel.HIGH,
            "client_cert": AssuranceLevel.HIGH,

            # Medium Assurance (Multi-factor / Out-of-band shared secrets)
            "totp": AssuranceLevel.MEDIUM,
            "authenticator_app": AssuranceLevel.MEDIUM,
            "otp": AssuranceLevel.MEDIUM,
            "sms_otp": AssuranceLevel.MEDIUM,
            "sms": AssuranceLevel.MEDIUM,
            "email_otp": AssuranceLevel.MEDIUM,
            "push_notification": AssuranceLevel.MEDIUM,

            # Low Assurance (Single-factor memorized secrets / legacy)
            "password": AssuranceLevel.LOW,
            "pin": AssuranceLevel.LOW,
            "knowledge_based": AssuranceLevel.LOW,
            "security_questions": AssuranceLevel.LOW,
        }

        # Detailed security rationale for each method category
        self._rationales: Dict[str, str] = {
            "passkey": "NIST SP 800-63B Authenticator Requirements (AAL2/AAL3-capable): Phishing-resistant asymmetric cryptographic keypair bound to origin, resistant to verifier-impersonation.",
            "fido2": "NIST SP 800-63B Hardware Authenticator (AAL3-capable): Hardware-backed cryptographic token resistant to verifier impersonation and credential relay.",
            "webauthn": "NIST SP 800-63B Cryptographic Authenticator (AAL2/AAL3-capable): Browser-standard public key credentials preventing credential relay.",
            "hardware_token": "NIST SP 800-63B Hardware Token (AAL3-capable): Physical cryptographic token requiring hardware possession.",
            "u2f": "NIST SP 800-63B Challenge-Response Authenticator (AAL2/AAL3-capable): Universal 2nd Factor challenge-response token.",
            "client_cert": "NIST SP 800-63B Cryptographic Authenticator (AAL3-capable): Mutual TLS client certificate backed by public key infrastructure.",

            "totp": "NIST SP 800-63B Multi-Factor Software Authenticator (AAL2): Time-based one-time password from authenticator app; possession-based but susceptible to proxy phishing.",
            "authenticator_app": "NIST SP 800-63B Software Authenticator (AAL2): Out-of-band software authenticator requiring device possession.",
            "otp": "NIST SP 800-63B Out-of-Band Authenticator (AAL2): One-time shared secret valid for single authentication session.",
            "sms_otp": "NIST SP 800-63B Out-of-Band Authenticator (AAL2 Restricted): Out-of-band SMS delivery; vulnerable to SIM-swap, SS7 interception, and phishing.",
            "sms": "NIST SP 800-63B Out-of-Band Authenticator (AAL2 Restricted): Telephony-based delivery channel with carrier dependencies.",
            "email_otp": "NIST SP 800-63B Out-of-Band Authenticator (AAL2 Restricted): Out-of-band email token vulnerable to mailbox compromise.",
            "push_notification": "NIST SP 800-63B Out-of-Band Authenticator (AAL2): Out-of-band push confirmation vulnerable to MFA fatigue / push-bombing.",

            "password": "NIST SP 800-63B Memorized Secret (AAL1): Single-factor memorized secret susceptible to credential stuffing, brute force, and phishing.",
            "pin": "NIST SP 800-63B Memorized Secret (AAL1): Short memorized secret with limited entropy.",
            "knowledge_based": "NIST SP 800-63B Prohibited / Deprecated: Static personal data easily harvestable via open source intelligence (OSINT).",
            "security_questions": "NIST SP 800-63B Prorecated: Weak static knowledge questions offering minimal security guarantee.",
        }

        if custom_mapping:
            self._mapping.update({k.lower().strip(): v for k, v in custom_mapping.items()})

    def get_assurance_level(self, method: Optional[str]) -> Tuple[AssuranceLevel, bool]:
        """
        Determines the assurance level for an authentication method.
        Returns a tuple: (AssuranceLevel, is_recognized: bool).
        Defensively defaults to LOW if unrecognized, ensuring fail-closed security.
        """
        if not method:
            return AssuranceLevel.LOW, False

        normalized = method.strip().lower()
        if normalized in self._mapping:
            return self._mapping[normalized], True

        return AssuranceLevel.LOW, False

    def get_rationale(self, method: Optional[str]) -> str:
        """
        Returns the security reasoning supporting the assurance classification.
        """
        if not method:
            return "No authentication method provided; default minimum assurance (LOW) applied."

        normalized = method.strip().lower()
        if normalized in self._rationales:
            return self._rationales[normalized]

        return (
            f"Unrecognized authentication method '{method}'. "
            "Defensively assigned to minimum assurance (LOW) to avoid unverified elevation."
        )

    def register_method(self, method: str, level: AssuranceLevel, rationale: str) -> None:
        """
        Dynamically registers or updates an authentication method.
        """
        normalized = method.strip().lower()
        self._mapping[normalized] = level
        self._rationales[normalized] = rationale
