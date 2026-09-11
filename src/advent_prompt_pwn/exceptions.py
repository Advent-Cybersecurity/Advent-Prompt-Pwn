"""Library exceptions."""


class AdventPromptPwnError(Exception):
    """Base exception for the package."""


class ConfigurationError(AdventPromptPwnError):
    """Raised when configuration is invalid."""


class ScopeViolation(AdventPromptPwnError):
    """Raised when a target falls outside the declared authorization scope."""


class BudgetExceeded(AdventPromptPwnError):
    """Raised when the request budget is exhausted."""


class TargetError(AdventPromptPwnError):
    """Raised when a model target cannot complete a request."""


class CorpusError(AdventPromptPwnError):
    """Raised when an attack corpus cannot be parsed or validated."""


class ReportError(AdventPromptPwnError):
    """Raised when report or evidence-bundle data is invalid."""


class EngagementError(AdventPromptPwnError):
    """Raised when an engagement manifest is invalid."""
