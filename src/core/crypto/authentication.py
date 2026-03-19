from datetime import datetime, timedelta
from typing import Optional

from ..events import Event, EventType, event_bus
from ..state_manager import StateManager
from .key_derivation import KeyDerivation
from .key_storage import KeyStorage
from .password_validator import PasswordValidator


class AuthenticationError(Exception):
    pass


class AuthenticationService:
    def __init__(
        self,
        key_storage: KeyStorage,
        key_derivation: KeyDerivation,
        password_validator: PasswordValidator,
        state_manager: Optional[StateManager] = None,
    ):
        self.key_storage = key_storage
        self.key_derivation = key_derivation
        self.password_validator = password_validator
        self.state_manager = state_manager or StateManager()
        self._failed_attempts = 0
        self._locked_until: Optional[datetime] = None

    def is_initialized(self) -> bool:
        return self.key_storage.has_master_key()

    def register_master_password(self, password: str):
        is_valid, errors = self.password_validator.validate(password, strict=True)
        if not is_valid:
            raise AuthenticationError("; ".join(errors))

        auth_data = self.key_derivation.create_auth_hash(password)
        encryption_key, encryption_salt = self.key_derivation.derive_encryption_key(password)
        self.key_storage.store_metadata(auth_data["hash"], encryption_salt, auth_data)
        self.key_storage.cache_active_key(encryption_key)
        self.state_manager.unlock()
        event_bus.publish(Event(EventType.USER_LOGGED_IN, {"initialized": True}))

    def authenticate(self, password: str) -> bool:
        if self._is_locked_out():
            return False

        metadata = self.key_storage.load_metadata()
        if metadata is None:
            raise AuthenticationError("Master password is not initialized")

        if not self.key_derivation.verify_auth_hash(password, metadata.hash):
            self._register_failure()
            return False

        encryption_key = self.key_derivation.derive_key_with_known_salt(password, metadata.salt)
        self.key_storage.cache_active_key(encryption_key)
        self.state_manager.unlock()
        self._failed_attempts = 0
        self._locked_until = None
        event_bus.publish(Event(EventType.USER_LOGGED_IN, {"initialized": False}))
        return True

    def change_master_password(self, current_password: str, new_password: str):
        if not self.authenticate(current_password):
            raise AuthenticationError("Current password is invalid")

        is_valid, errors = self.password_validator.validate(new_password, strict=True)
        if not is_valid:
            raise AuthenticationError("; ".join(errors))

        auth_data = self.key_derivation.create_auth_hash(new_password)
        encryption_key, encryption_salt = self.key_derivation.derive_encryption_key(new_password)
        self.key_storage.store_metadata(auth_data["hash"], encryption_salt, auth_data)
        self.key_storage.cache_active_key(encryption_key)

    def logout(self):
        self.key_storage.clear_cached_key()
        self.state_manager.lock()
        event_bus.publish(Event(EventType.USER_LOGGED_OUT, {}))

    def is_authenticated(self) -> bool:
        return self.state_manager.is_unlocked() and self.key_storage.get_cached_key() is not None

    def get_active_key(self) -> Optional[bytes]:
        return self.key_storage.get_cached_key()

    def get_lockout_remaining_seconds(self) -> int:
        if self._locked_until is None:
            return 0
        return max(0, int((self._locked_until - datetime.now()).total_seconds()))

    def load_password_policy(self) -> dict:
        policy = self.key_storage.database.get_setting("security.password_policy", default={})
        if isinstance(policy, dict):
            return policy
        return {}

    def save_password_policy(self, policy: dict):
        self.key_storage.database.set_setting("security.password_policy", policy)

    def _is_locked_out(self) -> bool:
        return self._locked_until is not None and datetime.now() < self._locked_until

    def _register_failure(self):
        self._failed_attempts += 1
        delay_seconds = min(2 ** min(self._failed_attempts, 6), 60)
        self._locked_until = datetime.now() + timedelta(seconds=delay_seconds)
