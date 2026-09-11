"""Library exceptions."""


class AdventPromptPwnError(Exception):
    """Base exception for the package."""

    diagnostic_code = "APPWN-E000"


class ConfigurationError(AdventPromptPwnError):
    """Raised when configuration is invalid."""

    diagnostic_code = "APPWN-E101"


class ScopeViolation(AdventPromptPwnError):
    """Raised when a target falls outside the declared authorization scope."""

    diagnostic_code = "APPWN-E201"


class BudgetExceeded(AdventPromptPwnError):
    """Raised when the request budget is exhausted."""

    diagnostic_code = "APPWN-E202"


class TargetError(AdventPromptPwnError):
    """Raised when a model target cannot complete a request."""

    diagnostic_code = "APPWN-E301"


class CorpusError(AdventPromptPwnError):
    """Raised when an attack corpus cannot be parsed or validated."""

    diagnostic_code = "APPWN-E401"


class ReportError(AdventPromptPwnError):
    """Raised when report or evidence-bundle data is invalid."""

    diagnostic_code = "APPWN-E501"


class EngagementError(AdventPromptPwnError):
    """Raised when an engagement manifest is invalid."""

    diagnostic_code = "APPWN-E601"
