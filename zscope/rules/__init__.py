"""Rule governance, extension, and execution interfaces."""

from .catalog import (
    EffectiveRuleSet,
    RuleCatalog,
    RuleCatalogError,
    RuleCatalogProvenance,
    RuleDescriptor,
    RulePolicy,
    serialize_effective_rules,
)
from .extensions import Candidate, ExecutableRule, RuleContext, RulePackError, preflight_rules
from .qualification import (
    QualificationRegistry,
    RuleQualification,
    qualification_rows,
)
from .qualification_evidence import (
    QUALIFICATION_EVIDENCE_SCHEMA_VERSION,
    QualificationEvidenceSummary,
    load_qualification_evidence,
)
from .validation_obligations import (
    VALIDATION_OBLIGATION_CATALOG_VERSION,
    ValidationObligationBinding,
    ValidationObligationProfile,
    attach_obligation_binding,
    binding_for_issue,
    binding_for_rule,
    builtin_obligation_coverage,
    profile_for_defect_class,
)

__all__ = [
    "Candidate",
    "EffectiveRuleSet",
    "ExecutableRule",
    "RuleCatalog",
    "RuleCatalogError",
    "RuleCatalogProvenance",
    "RuleContext",
    "RuleDescriptor",
    "RulePackError",
    "RulePolicy",
    "QualificationRegistry",
    "QualificationEvidenceSummary",
    "QUALIFICATION_EVIDENCE_SCHEMA_VERSION",
    "RuleQualification",
    "preflight_rules",
    "serialize_effective_rules",
    "qualification_rows",
    "load_qualification_evidence",
    "VALIDATION_OBLIGATION_CATALOG_VERSION",
    "ValidationObligationBinding",
    "ValidationObligationProfile",
    "attach_obligation_binding",
    "binding_for_issue",
    "binding_for_rule",
    "builtin_obligation_coverage",
    "profile_for_defect_class",
]
