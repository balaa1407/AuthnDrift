"""
AuthDrift: Keycloak Event Extractor.
Extracts raw authentication event logs directly from Keycloak's Admin REST API.
"""

import json
from typing import Any, Dict, List, Optional
import requests


class KeycloakEventExtractor:
    """
    Client for extracting authentication events from Keycloak's REST API.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        realm: str = "authdrift",
        admin_username: str = "admin",
        admin_password: str = "admin",
        admin_realm: str = "master",
        verify_ssl: bool = True
    ):
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.admin_realm = admin_realm
        self.verify_ssl = verify_ssl
        self._access_token: Optional[str] = None

    def authenticate(self) -> str:
        """
        Authenticates against Keycloak master realm using admin credentials.
        Returns the OAuth2 access token.
        """
        token_endpoint = f"{self.base_url}/realms/{self.admin_realm}/protocol/openid-connect/token"
        payload = {
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": self.admin_username,
            "password": self.admin_password
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.post(
            token_endpoint,
            data=payload,
            headers=headers,
            verify=self.verify_ssl,
            timeout=10
        )
        response.raise_for_status()
        token_data = response.json()
        self._access_token = token_data.get("access_token")
        if not self._access_token:
            raise ValueError("Authentication response did not contain an access_token.")
        return self._access_token

    def fetch_events(
        self,
        user_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        client: Optional[str] = None,
        first: int = 0,
        max_events: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieves user authentication events from the Keycloak Admin API.
        """
        if not self._access_token:
            self.authenticate()

        events_endpoint = f"{self.base_url}/admin/realms/{self.realm}/events"
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json"
        }
        params: Dict[str, Any] = {
            "first": first,
            "max": max_events
        }
        if user_id:
            params["user"] = user_id
        if client:
            params["client"] = client
        if event_types:
            params["type"] = event_types

        try:
            response = requests.get(
                events_endpoint,
                headers=headers,
                params=params,
                verify=self.verify_ssl,
                timeout=10
            )
            # Re-authenticate if token expired
            if response.status_code == 401:
                self.authenticate()
                headers["Authorization"] = f"Bearer {self._access_token}"
                response = requests.get(
                    events_endpoint,
                    headers=headers,
                    params=params,
                    verify=self.verify_ssl,
                    timeout=10
                )

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ConnectionError(
                f"Failed to connect to Keycloak at {self.base_url}: {e}"
            ) from e

    def export_events_to_file(self, filepath: str, max_events: int = 500) -> int:
        """
        Exports extracted Keycloak events into a JSON file on disk.
        """
        events = self.fetch_events(max_events=max_events)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
        return len(events)

