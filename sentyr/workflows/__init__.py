"""Automated workflows for common security use cases."""

from sentyr.workflows.external_pii_alert import (
    ExternalPIIAlertWorkflow,
    ExternalPIIAlertConfig,
    ExternalPIIAlertResult,
)
from sentyr.workflows.gmail_external_pii_alert import (
    GmailExternalPIIAlertWorkflow,
    GmailExternalPIIAlertConfig,
    GmailExternalPIIAlertResult,
)

__all__ = [
    "ExternalPIIAlertWorkflow",
    "ExternalPIIAlertConfig",
    "ExternalPIIAlertResult",
    "GmailExternalPIIAlertWorkflow",
    "GmailExternalPIIAlertConfig",
    "GmailExternalPIIAlertResult",
]

