"""Integration modules for external services (Slack, email, SIEM, etc.)."""

from sentyr.integrations.email import EmailAlerter, EmailError
from sentyr.integrations.slack import SlackAlerter, SlackError
from sentyr.integrations.webhook import (
    WebhookSender,
    WebhookConfig,
    WebhookFormat,
    WebhookError,
    WebhookAuth,
    WebhookAuthType,
    WebhookRetryConfig,
)

__all__ = [
    "EmailAlerter",
    "EmailError",
    "SlackAlerter",
    "SlackError",
    "WebhookSender",
    "WebhookConfig",
    "WebhookFormat",
    "WebhookError",
    "WebhookAuth",
    "WebhookAuthType",
    "WebhookRetryConfig",
]
