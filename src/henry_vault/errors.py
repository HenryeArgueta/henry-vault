class VaultError(Exception):
    """Base class for vault errors."""


class VaultAlreadyExists(VaultError):
    """Raised when initializing over an existing vault."""


class VaultNotInitialized(VaultError):
    """Raised when a vault database has not been initialized."""


class VaultLocked(VaultError):
    """Raised when a vault cannot be unlocked or used while locked."""
