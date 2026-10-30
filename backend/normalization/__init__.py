"""
AuthDrift: Event Normalization Layer.
Standardizes raw identity provider logs (Keycloak, Okta, etc.) into the vendor-neutral
AuthenticationEvent common schema.
"""

from backend.normalization.base import BaseEventNormalizer
from backend.normalization.keycloak import KeycloakEventNormalizer
from backend.normalization.okta import OktaEventNormalizer
from backend.normalization.deduplicator import EventDeduplicator

__all__ = [
    "BaseEventNormalizer",
    "KeycloakEventNormalizer",
    "OktaEventNormalizer",
    "EventDeduplicator",
]

