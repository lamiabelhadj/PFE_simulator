"""

The auth server performs:
- Token issuance
- Token validation
- Policy/authorization management
- Device registry management
"""

import logging
from typing import Optional
from datetime import datetime, timedelta
from ..models.token import Token
from ..models.device import Device

logger = logging.getLogger(__name__)


class AuthServer:
    """
    Cloud/Auth Server component for IoT authentication.
    
    Manages token issuance, validation, and authorization policies.
    """
    
    def __init__(self, server_id: str):
        """
        Initialize auth server.
        
        Args:
            server_id: Unique identifier for this server
        """
        self.server_id = server_id
        self.device_registry: dict[str, Device] = {}
        self.issued_tokens: dict[str, Token] = {}
        self.token_expiration_hours = 1
    
    def register_device(self, device: Device) -> bool:
        """
        Register a device in the registry.
        
        Args:
            device: Device to register
            
        Returns:
            True if registration successful
        """
        self.device_registry[device.device_id] = device
        logger.info(f"AuthServer {self.server_id}: Registered device {device.device_id}")
        return True
    
    def is_device_known(self, device_id: str) -> bool:
        """
        Check if device is in registry.
        
        Args:
            device_id: Device ID to check
            
        Returns:
            True if device is known
        """
        return device_id in self.device_registry
    
    def issue_token(self, device_id: str, scope: str = "sensors/*") -> Optional[Token]:
        """
        Issue a token to a device.
        
        Args:
            device_id: Device to issue token for
            scope: Token authorization scope
            
        Returns:
            Issued Token or None if device not in registry
        """
        if device_id not in self.device_registry:
            logger.warning(f"AuthServer {self.server_id}: Cannot issue token to unknown device {device_id}")
            return None
        
        token = Token(
            device_id=device_id,
            scope=scope,
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=self.token_expiration_hours),
        )
        
        self.issued_tokens[token.token_id] = token
        logger.info(f"AuthServer {self.server_id}: Issued token {token.token_id[:8]}... to {device_id}")
        return token
    
    def validate_token(self, token_id: str, device_id: str) -> bool:
        """
        Validate a token for a device.
        
        Args:
            token_id: Token to validate
            device_id: Device using the token
            
        Returns:
            True if token is valid
        """
        if token_id not in self.issued_tokens:
            logger.warning(f"AuthServer {self.server_id}: Token {token_id[:8]}... not found")
            return False
        
        token = self.issued_tokens[token_id]
        
        # Check device match
        if token.device_id != device_id:
            logger.warning(f"AuthServer {self.server_id}: Token device mismatch")
            return False
        
        # Check expiration
        if token.is_expired():
            logger.warning(f"AuthServer {self.server_id}: Token {token_id[:8]}... expired")
            return False
        
        logger.info(f"AuthServer {self.server_id}: Token {token_id[:8]}... validated for {device_id}")
        return True
    
    def revoke_token(self, token_id: str) -> bool:
        """
        Revoke a token.
        
        Args:
            token_id: Token to revoke
            
        Returns:
            True if revocation successful
        """
        if token_id not in self.issued_tokens:
            return False
        
        del self.issued_tokens[token_id]
        logger.info(f"AuthServer {self.server_id}: Revoked token {token_id[:8]}...")
        return True
    
    def __str__(self) -> str:
        return f"AuthServer({self.server_id}, devices={len(self.device_registry)}, tokens={len(self.issued_tokens)})"
