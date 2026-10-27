"""
Unit tests for AuthDrift Assurance Model and Assignment (Objective 2).
"""

import pytest
from backend.models.assurance import AssuranceLevel
from backend.assurance.assurance_model import AssuranceModel
from backend.assurance.assurance_assignment import (
    assign_assurance,
    get_assurance_justification,
    is_high_assurance
)


class TestAssuranceModel:
    def test_high_assurance_methods(self):
        for method in ["passkey", "fido2", "webauthn", "hardware_token", "u2f", "client_cert"]:
            assert assign_assurance(method) == AssuranceLevel.HIGH
            assert is_high_assurance(method) is True

    def test_medium_assurance_methods(self):
        for method in ["totp", "otp", "sms_otp", "sms", "email_otp", "authenticator_app"]:
            assert assign_assurance(method) == AssuranceLevel.MEDIUM
            assert is_high_assurance(method) is False

    def test_low_assurance_methods(self):
        for method in ["password", "pin", "knowledge_based", "security_questions"]:
            assert assign_assurance(method) == AssuranceLevel.LOW
            assert is_high_assurance(method) is False

    def test_case_insensitivity_and_whitespace(self):
        assert assign_assurance("  PASSKEY  ") == AssuranceLevel.HIGH
        assert assign_assurance("PassKey") == AssuranceLevel.HIGH
        assert assign_assurance("ToTp") == AssuranceLevel.MEDIUM
        assert assign_assurance("PassWord") == AssuranceLevel.LOW

    def test_unknown_method_defensive_fallback(self):
        # Fail-closed security principle: unverified methods must NEVER default to HIGH
        level = assign_assurance("unrecognized_experimental_biometric")
        assert level == AssuranceLevel.LOW
        
        model = AssuranceModel()
        lvl, recognized = model.get_assurance_level("unrecognized_experimental_biometric")
        assert lvl == AssuranceLevel.LOW
        assert recognized is False

    def test_none_and_empty_handling(self):
        assert assign_assurance(None) == AssuranceLevel.LOW
        assert assign_assurance("") == AssuranceLevel.LOW
        assert assign_assurance("   ") == AssuranceLevel.LOW

    def test_assurance_level_comparisons(self):
        assert AssuranceLevel.LOW < AssuranceLevel.MEDIUM
        assert AssuranceLevel.MEDIUM < AssuranceLevel.HIGH
        assert AssuranceLevel.LOW < AssuranceLevel.HIGH
        assert AssuranceLevel.HIGH > AssuranceLevel.LOW

    def test_rationales_documentation(self):
        justification = get_assurance_justification("passkey")
        assert "NIST SP 800-63B" in justification
        assert "phishing-resistant" in justification.lower()

        unknown_justification = get_assurance_justification("unknown_method")
        assert "defensively" in unknown_justification.lower()

    def test_dynamic_method_registration(self):
        model = AssuranceModel()
        model.register_method("enterprise_smartcard", AssuranceLevel.HIGH, "PIV smartcard hardware token")
        level, recognized = model.get_assurance_level("enterprise_smartcard")
        assert level == AssuranceLevel.HIGH
        assert recognized is True
        assert "smartcard" in model.get_rationale("enterprise_smartcard").lower()
