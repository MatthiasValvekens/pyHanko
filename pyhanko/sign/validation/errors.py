__all__ = [
    'SignatureValidationError', 'WeakHashAlgorithmError',
    'ValidationInfoReadingError', 'NoDSSFoundError',
    'SigSeedValueValidationError',
]


class ValidationInfoReadingError(ValueError):
    """Error reading validation info."""
    pass


class NoDSSFoundError(ValidationInfoReadingError):
    def __init__(self):
        super().__init__("No DSS found")


class SignatureValidationError(ValueError):
    """Error validating a signature."""
    pass


class WeakHashAlgorithmError(SignatureValidationError):
    pass


class SigSeedValueValidationError(SignatureValidationError):
    """Error validating a signature's seed value constraints."""

    # TODO perhaps we can encode some more metadata here, such as the
    #  seed value that tripped the failure.

    def __init__(self, failure_message):
        self.failure_message = str(failure_message)
        super().__init__(failure_message)
