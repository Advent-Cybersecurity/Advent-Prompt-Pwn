"""Public API for advent-prompt-pwn."""

from importlib.metadata import PackageNotFoundError, version

from advent_prompt_pwn.bundle import (
    BundleVerification,
    verify_evidence_bundle,
    write_evidence_bundle,
)
from advent_prompt_pwn.comparison import ReportComparison, compare_reports, save_comparison
from advent_prompt_pwn.core.models import (
    AttackCase,
    AttackVariant,
    AttemptResult,
    Finding,
    Message,
    OracleResult,
    Role,
    RunReport,
    Severity,
    TargetResponse,
    ToolCall,
    TrialStatistic,
)
from advent_prompt_pwn.core.runner import (
    RunConfig,
    Runner,
    run,
    verify_checkpoint_authentication,
)
from advent_prompt_pwn.core.scope import Scope
from advent_prompt_pwn.corpus import (
    CorpusDefinition,
    load_corpus,
    load_corpus_definition,
    write_starter_corpus,
)
from advent_prompt_pwn.engagement import (
    EngagementDefinition,
    EngagementPlan,
    EngagementRun,
    load_engagement,
    plan_engagement,
    run_engagement,
    write_starter_engagement,
)
from advent_prompt_pwn.oracles import (
    AllOracle,
    AnyOracle,
    CanaryLeakOracle,
    ContainsAllOracle,
    ContainsAnyOracle,
    ContainsOracle,
    JsonKeysOracle,
    JsonPathOracle,
    RegexOracle,
    ToolCallOracle,
)
from advent_prompt_pwn.report_io import load_report, verify_report_evidence
from advent_prompt_pwn.reporters import save_report
from advent_prompt_pwn.reproducers import (
    MinimalReproducer,
    save_minimal_reproducers,
    select_minimal_reproducers,
)
from advent_prompt_pwn.schema import get_schema
from advent_prompt_pwn.strategies import (
    CompositeStrategy,
    DelimiterStrategy,
    DirectStrategy,
    EncodingStrategy,
    IndirectDocumentStrategy,
    IndirectFixtureStrategy,
    InstructionOverrideStrategy,
    MultiTurnStrategy,
    RoleConfusionStrategy,
)
from advent_prompt_pwn.targets import (
    FakeTarget,
    FunctionTarget,
    HttpJsonTarget,
    OllamaTarget,
    OpenAICompatibleTarget,
)

try:
    __version__ = version("advent-prompt-pwn")
except PackageNotFoundError:
    __version__ = "1.0.0"

__all__ = [
    "AllOracle",
    "AnyOracle",
    "AttackCase",
    "AttackVariant",
    "AttemptResult",
    "BundleVerification",
    "CanaryLeakOracle",
    "CompositeStrategy",
    "ContainsAllOracle",
    "ContainsAnyOracle",
    "ContainsOracle",
    "CorpusDefinition",
    "DelimiterStrategy",
    "DirectStrategy",
    "EncodingStrategy",
    "EngagementDefinition",
    "EngagementPlan",
    "EngagementRun",
    "FakeTarget",
    "Finding",
    "FunctionTarget",
    "HttpJsonTarget",
    "IndirectDocumentStrategy",
    "IndirectFixtureStrategy",
    "InstructionOverrideStrategy",
    "JsonKeysOracle",
    "JsonPathOracle",
    "Message",
    "MinimalReproducer",
    "MultiTurnStrategy",
    "OllamaTarget",
    "OpenAICompatibleTarget",
    "OracleResult",
    "RegexOracle",
    "ReportComparison",
    "Role",
    "RoleConfusionStrategy",
    "RunConfig",
    "RunReport",
    "Runner",
    "Scope",
    "Severity",
    "TargetResponse",
    "ToolCall",
    "ToolCallOracle",
    "TrialStatistic",
    "__version__",
    "compare_reports",
    "get_schema",
    "load_corpus",
    "load_corpus_definition",
    "load_engagement",
    "load_report",
    "plan_engagement",
    "run",
    "run_engagement",
    "save_comparison",
    "save_minimal_reproducers",
    "save_report",
    "select_minimal_reproducers",
    "verify_checkpoint_authentication",
    "verify_evidence_bundle",
    "verify_report_evidence",
    "write_evidence_bundle",
    "write_starter_corpus",
    "write_starter_engagement",
]
