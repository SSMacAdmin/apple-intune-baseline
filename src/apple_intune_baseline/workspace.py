"""Workspace storage seam.

The workspace holds everything the person tailors: custom baselines, ODV
overrides, exception reasons and (later) the compliance selection. Today it
is a local folder, ideally a git repo. A hosted mode would add another
implementation of :class:`Workspace` (per-user storage) without touching the
tools.

The workspace doubles as mSCP's *custom directory*, so tailoring stays in
mSCP's own format and mSCP's own loaders pick it up.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol, runtime_checkable

DEFAULT_HOME_ENV = "APPLE_INTUNE_BASELINE_HOME"
DEFAULT_HOME = Path("~/.apple-intune-baseline").expanduser()


@runtime_checkable
class Workspace(Protocol):
    """Where tailored state lives. Implementations must be safe to read concurrently."""

    @property
    def mscp_custom_dir(self) -> Path:
        """Directory mSCP treats as its ``custom/`` tree."""
        ...

    @property
    def state_dir(self) -> Path:
        """Where per-workspace state lives: tenant config, token cache signal file."""
        ...

    def describe(self) -> dict:
        """Short, user-facing description for status output."""
        ...


class LocalWorkspace:
    """A folder on the person's Mac. Created on first use."""

    def __init__(self, root: Path | None = None) -> None:
        env = os.environ.get(DEFAULT_HOME_ENV)
        self.root = (root or (Path(env).expanduser() if env else DEFAULT_HOME)).resolve()

    @property
    def mscp_custom_dir(self) -> Path:
        return self.root / "mscp-custom"

    @property
    def state_dir(self) -> Path:
        return self.root

    def ensure(self) -> None:
        for sub in ("baselines", "rules", "sections"):
            (self.mscp_custom_dir / sub).mkdir(parents=True, exist_ok=True)

    def describe(self) -> dict:
        return {
            "kind": "local",
            "path": str(self.root),
            "is_git_repo": (self.root / ".git").exists(),
        }
