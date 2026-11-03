"""Thin access layer over mSCP's own Python API.

Everything here delegates to mSCP (``mscp.classes.baseline.Baseline`` and
friends) instead of re-parsing rule YAML, so upstream changes to the rule
schema stay upstream's problem. The pinned mSCP release is declared in
``pyproject.toml``.
"""

from __future__ import annotations

import importlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from .errors import UserInputError
from .platforms import Platform

if TYPE_CHECKING:
    from mscp.classes.baseline import Baseline
    from mscp.classes.macsecurityrule import Macsecurityrule

    from .workspace import Workspace

def _norm_version(v: str | float) -> str:
    """'26', '26.0', 26 -> '26.0'."""
    try:
        return f"{float(str(v).strip()):.1f}"
    except ValueError:
        raise UserInputError(f"'{v}' is not an OS version such as '26.0'.") from None


_BASELINE_STEM = re.compile(r"^(?P<key>.+)_(?P<os>macos|ios|visionos)_(?P<ver>\d+\.\d+)$")


def _quiet_mscp() -> None:
    """mSCP logs through loguru to stderr; keep MCP stdio output clean."""
    from loguru import logger

    logger.remove()


@dataclass(frozen=True)
class BaselineRef:
    """A baseline file, bundled with mSCP or tailored in the workspace."""

    key: str  # e.g. "cis_lvl1"
    platform: Platform
    os_version: str  # e.g. "27.0"
    path: Path
    source: str  # "mscp" | "workspace"

    @property
    def name(self) -> str:
        return f"{self.key}_{self.platform.value}_{self.os_version}"


class MscpSource:
    """Lists and loads mSCP baselines and rules for one workspace."""

    def __init__(self, workspace: Workspace) -> None:
        _quiet_mscp()
        # mscp.common_utils re-exports a ``config`` dict that shadows the module itself.
        mscp_config = importlib.import_module("mscp.common_utils.config")

        self._config = mscp_config.config
        self.workspace = workspace
        # Make the workspace mSCP's custom/ tree so tailoring stays in mSCP's format.
        mscp_config.set_custom_dir(workspace.mscp_custom_dir)
        self._bundled_dir = Path(self._config["baseline_dir"])
        # Baselines for other OS versions mSCP supports (e.g. macOS 26), built on demand with
        # mSCP's own generator: the release ships only its newest version's files.
        self._versions_dir = workspace.state_dir / "mscp-baselines"
        self._load_cached = lru_cache(maxsize=32)(self._load_uncached)

    # ------------------------------------------------------------------ info

    @property
    def mscp_version(self) -> str:
        """The pinned mSCP release tag (e.g. ``release_27.0``) plus the package version."""
        try:
            dist = distribution("mscp")
        except PackageNotFoundError:  # pragma: no cover - source checkout
            return "unknown"
        release = None
        try:
            info = json.loads(dist.read_text("direct_url.json") or "{}")
            vcs = info.get("vcs_info", {})
            release = vcs.get("requested_revision") or (vcs.get("commit_id") or "")[:12] or None
        except (ValueError, TypeError):
            pass
        return f"{release} (mscp {dist.version})" if release else dist.version

    # ------------------------------------------------------------- baselines

    def supported_versions(self, platform: Platform) -> list[str]:
        """OS versions mSCP has rule data for, newest first (e.g. macOS 27.0, 26.0, 15.0)."""
        from mscp.common_utils import mscp_data

        entries = mscp_data.get("versions", {}).get("platforms", {}).get(platform.value, [])
        return sorted({f"{float(e['os_version']):.1f}" for e in entries}, key=float, reverse=True)

    def bundled_versions(self, platform: Platform) -> set[str]:
        return {r.os_version for r in self._refs_in(self._bundled_dir / platform.value, platform)}

    def ensure_version(self, platform: Platform, os_version: str) -> None:
        """Make the baselines for an OS version available, building them once if mSCP ships none."""
        ver = _norm_version(os_version)
        if ver in self.bundled_versions(platform):
            return
        supported = self.supported_versions(platform)
        if ver not in supported:
            raise UserInputError(
                f"mSCP {self.mscp_version} has no {platform.display} {ver} rules. "
                f"Supported: {', '.join(supported)}")
        folder = self._versions_dir / f"{platform.value}_{ver}"
        marker = folder / ".mscp-release"
        if marker.exists() and marker.read_text(encoding="utf-8") == self.mscp_version:
            return
        self._build_version(platform, float(ver), folder)
        marker.write_text(self.mscp_version, encoding="utf-8")
        self.invalidate()

    def _build_version(self, platform: Platform, ver: float, folder: Path) -> None:
        """mSCP's own baseline generator (as `mscp admin baselines` does), for one platform and
        version. Byte-identical to the bundled files when run for the bundled version."""
        import argparse
        import contextlib
        import io
        import shutil

        from mscp.classes.rule_library import RuleLibrary
        from mscp.common_utils import logging_config
        from mscp.generate import generate_baseline
        from mscp.generate.baseline import collect_tags_and_benchmarks

        excluded = {"arm64", "i386", "inherent", "manual", "n_a", "none", "permanent", "supplemental",
                    "800-53r5_privacy"}
        incomplete = {"macos": {"cmmc_lvl3"}, "ios": {"hicp_lp"}}  # mSCP leaves these out too
        tmp = folder.with_name(folder.name + ".building")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        saved_dir = self._config["baseline_dir"]
        logging_config.suppress_spinner = True
        try:
            self._config["baseline_dir"] = str(tmp)
            library = RuleLibrary.from_rules_dir()
            tags, benchmarks = collect_tags_and_benchmarks(list(library))
            rules = list(library.by_platform(platform.value).by_os(os_version=ver))
            keywords = [k for k, plats in benchmarks.items() if platform.value in {p.lower() for p in plats}]
            keywords += [t for t in tags if t not in excluded and t not in incomplete.get(platform.value, set())
                         and t not in keywords]
            # mSCP prints progress to stdout, which is this server's MCP channel: keep it out
            with contextlib.redirect_stdout(io.StringIO()):
                for keyword in keywords:
                    args = argparse.Namespace(os_name=platform.value, os_version=ver, keyword=keyword,
                                              tailor=False, list_tags=False, controls=False)
                    generate_baseline(args, admin=True, preloaded_rules=rules)
        finally:
            self._config["baseline_dir"] = saved_dir
        built = tmp / platform.value
        shutil.rmtree(folder, ignore_errors=True)
        folder.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(built if built.is_dir() else tmp), str(folder))
        shutil.rmtree(tmp, ignore_errors=True)

    def _refs_in(self, folder: Path, platform: Platform) -> list[BaselineRef]:
        refs = []
        for path in sorted(folder.glob("*.y*ml")):
            ref = self._ref_from_stem(path, "mscp")
            if ref and ref.platform is platform:
                refs.append(ref)
        return refs

    def list_baselines(self, platform: Platform, os_version: str | None = None) -> list[BaselineRef]:
        """Bundled baselines, those built for other OS versions, and tailored ones. With os_version,
        that version's are built first if needed."""
        if os_version:
            self.ensure_version(platform, os_version)
        refs: list[BaselineRef] = list(self._refs_in(self._bundled_dir / platform.value, platform))
        for folder in sorted(self._versions_dir.glob(f"{platform.value}_*")):
            if (folder / ".mscp-release").exists():
                refs += self._refs_in(folder, platform)
        custom_dir = self.workspace.mscp_custom_dir / "baselines"
        if custom_dir.is_dir():
            for path in sorted(custom_dir.rglob("*.y*ml")):
                ref = self._ref_from_file(path) or self._ref_from_stem(path, "workspace")
                if ref and ref.platform is platform:
                    refs.append(ref)
        return refs

    def resolve(self, name: str, platform: Platform, os_version: str | None = None) -> BaselineRef:
        """Find a baseline by short key (``cis_lvl1``) or full stem.

        Workspace (tailored) baselines win over bundled ones with the same key.
        """
        wanted = name.strip().removesuffix(".yaml").removesuffix(".yml")
        os_version = _norm_version(os_version) if os_version else None
        refs = self.list_baselines(platform, os_version)
        matches = [r for r in refs if wanted in (r.name, r.key, r.path.stem)]
        if os_version:
            matches = [r for r in matches if r.os_version == os_version]
        else:  # without a version: the newest mSCP ships, unless only a tailored copy exists
            newest = self.latest_os_version(platform)
            preferred = [r for r in matches if r.os_version == newest or r.source == "workspace"]
            matches = preferred or matches
        if not matches:
            known = sorted({r.key for r in refs})
            raise UserInputError(
                f"No {platform.display} baseline named '{name}'. Available: {', '.join(known)}"
            )
        matches.sort(key=lambda r: (r.source == "workspace", float(r.os_version)), reverse=True)
        return matches[0]

    def invalidate(self) -> None:
        """Forget loaded baselines, e.g. after a rule customization changed."""
        self._load_cached.cache_clear()

    @property
    def custom_rules_dir(self) -> Path:
        return Path(self._config["custom"]["rules_dir"])

    @property
    def custom_baselines_dir(self) -> Path:
        return self.workspace.mscp_custom_dir / "baselines"

    def load(self, ref: BaselineRef) -> Baseline:
        return self._load_cached(ref.path, ref.path.stat().st_mtime)

    def _load_uncached(self, path: Path, _mtime: float) -> Baseline:
        from mscp.classes.baseline import Baseline

        return Baseline.from_yaml(path)

    # ----------------------------------------------------------------- rules

    def rule_library(self, platform: Platform, os_version: str | None = None) -> dict[str, Macsecurityrule]:
        """Every rule mSCP has for the platform, keyed by rule ID (from ``all_rules``)."""
        ref = self.resolve("all_rules", platform, os_version)
        return {r.rule_id: r for p in self.load(ref).profile for r in p.rules}

    def latest_os_version(self, platform: Platform) -> str:
        return max(self.bundled_versions(platform), key=float)

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _ref_from_stem(path: Path, source: str) -> BaselineRef | None:
        m = _BASELINE_STEM.match(path.stem)
        if not m or m["os"] not in {p.value for p in Platform}:
            return None
        return BaselineRef(m["key"], Platform(m["os"]), m["ver"], path, source)

    @staticmethod
    def _ref_from_file(path: Path) -> BaselineRef | None:
        """Workspace baselines may be named freely; read ``platform`` from the file."""
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            os_name = str(data["platform"]["os"]).lower()
            ver = f"{float(data['platform']['version']):.1f}"
        except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError):
            return None
        if os_name not in {p.value for p in Platform}:
            return None
        m = _BASELINE_STEM.match(path.stem)
        key = m["key"] if m else path.stem
        return BaselineRef(key, Platform(os_name), ver, path, "workspace")
