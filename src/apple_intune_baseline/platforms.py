"""Platforms supported by this MCP and how they map onto mSCP names.

Only macOS and iOS/iPadOS are in scope. mSCP also ships visionOS and Linux
content; both are deliberately excluded.
"""

from __future__ import annotations

from enum import StrEnum

from .errors import UserInputError


class Platform(StrEnum):
    """A platform the MCP can check or generate for.

    ``ios`` covers iPhone and iPad together, as both mSCP and Intune treat
    iOS/iPadOS as one platform. iPad-only targeting belongs to an Intune
    assignment filter, not to a separate baseline.
    """

    MACOS = "macos"
    IOS = "ios"

    @property
    def mscp_os(self) -> str:
        """The OS name as mSCP (baseline ``platform.os``), Apple's schema and Graph's
        ``platforms`` filter all spell it."""
        return {"macos": "macOS", "ios": "iOS"}[self.value]

    @property
    def custom_profile_type(self) -> str:
        """Graph ``@odata.type`` of a custom configuration profile (.mobileconfig)."""
        return {"macos": "#microsoft.graph.macOSCustomConfiguration",
                "ios": "#microsoft.graph.iosCustomConfiguration"}[self.value]

    @property
    def compliance_policy_type(self) -> str:
        """Graph ``@odata.type`` of a compliance policy."""
        return {"macos": "#microsoft.graph.macOSCompliancePolicy",
                "ios": "#microsoft.graph.iosCompliancePolicy"}[self.value]

    @property
    def display(self) -> str:
        return {"macos": "macOS", "ios": "iOS/iPadOS"}[self.value]

    @property
    def supports_custom_compliance(self) -> bool:
        """Intune custom compliance needs a shell discovery script; iOS has none."""
        return self is Platform.MACOS


def parse_platform(value: str | Platform | None) -> Platform:
    """Accept loose spellings (``macOS``, ``iPadOS``, ``iOS/iPadOS``)."""
    if value is None:
        return Platform.MACOS
    if isinstance(value, Platform):
        return value
    v = value.strip().lower().replace(" ", "")
    if v in {"macos", "mac", "osx"}:
        return Platform.MACOS
    if v in {"ios", "ipados", "ios/ipados", "iphone", "ipad"}:
        return Platform.IOS
    raise UserInputError(
        f"Unsupported platform '{value}'. Use 'macos' or 'ios' (iOS/iPadOS). "
        "Linux and visionOS are out of scope."
    )
