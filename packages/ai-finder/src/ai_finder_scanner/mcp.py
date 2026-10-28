"""MCP (Model Context Protocol) detection.

Two sources, because an MCP server reaches a project in two ways:

- **Config**: an MCP client config (`.mcp.json`, `claude_desktop_config.json`,
  `.vscode/mcp.json`, ...) names each server and how to launch it. The launch
  command names the package (`npx -y @modelcontextprotocol/server-github`), so
  this is the provenance of a third-party server.
- **Code**: source that builds a server or a client with an MCP SDK, or that
  launches a known server package itself.

Both resolve package names against the KB `mcp_servers` table when a matcher is
given. A server the KB does not know is still reported: the config saying it is
an MCP server is the evidence, the KB only adds the identity.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .detectors.base import BaseDetector
from .models import Finding, FindingType, MCPInfo

logger = logging.getLogger(__name__)

# Keys under which client configs list their servers. `mcpServers` is Claude
# Desktop, Claude Code (.mcp.json), Cursor, Cline and Windsurf; `servers` is VS
# Code's .vscode/mcp.json; `context_servers` is Zed.
_SERVER_KEYS = ("mcpServers", "servers", "context_servers")

# Launchers whose first positional argument is a registry package.
_NPM_LAUNCHERS = frozenset({"npx", "bunx", "pnpx"})
_PYPI_LAUNCHERS = frozenset({"uvx"})
_CONTAINER_LAUNCHERS = frozenset({"docker", "podman"})

# docker/podman run flags that take a value, so the value is not the image.
_CONTAINER_VALUE_FLAGS = frozenset(
    {
        "-e",
        "--env",
        "--env-file",
        "-v",
        "--volume",
        "--name",
        "-p",
        "--publish",
        "--network",
        "--mount",
        "-w",
        "--workdir",
        "-u",
        "--user",
        "--entrypoint",
        "--platform",
        "-l",
        "--label",
    }
)
# uvx/npx flags that take a value.
_LAUNCHER_VALUE_FLAGS = frozenset({"--from", "--with", "-p", "--package", "--python", "--index"})


# What a registry package spec may look like. Anything else a launcher is handed
# (a URL, a tarball, a path) is not a registry package and must not become a
# purl: those are also where credentials ride (`https://u:pw@host/x.tgz`).
_NPM_SPEC = re.compile(r"^(@[a-z0-9][\w.\-~]*/)?[a-z0-9][\w.\-~]*(@[\w.\-+^~]+)?$", re.IGNORECASE)
_PYPI_SPEC = re.compile(r"^[a-z0-9][\w.\-]*(\[[\w,\-]+\])?((==|@)[\w.\-+]+)?$", re.IGNORECASE)
_IMAGE_REPO = re.compile(r"^[a-z0-9][a-z0-9._\-/]*$")
_IMAGE_TAG = re.compile(r"^[\w][\w.\-]{0,127}$")


def _is_version(version: str | None, ecosystem: str) -> bool:
    """A real version, not a moving tag such as `latest`, `next` or `stable`."""
    if not version:
        return False
    if ecosystem == "docker":
        return bool(re.match(r"^v?\d", version)) or version.startswith("sha256:")
    return version[0].isdigit()


def _split_version(spec: str, ecosystem: str) -> tuple[str, str | None] | None:
    """Split a registry spec into (name, version), or None if it is not one.

    `pkg@1.2.3` / `@scope/pkg@1` (npm), `pkg==1.2` / `pkg@1.2` (pypi). A dist-tag
    such as `@latest` is dropped rather than reported: it names whatever was
    newest on the day the launcher ran, not a version.
    """
    if ecosystem == "pypi":
        if not _PYPI_SPEC.match(spec):
            return None
        m = re.match(r"^(.+?)(?:==|@)([\w.\-+]+)$", spec)
        name, version = (m.group(1), m.group(2)) if m else (spec, None)
        name = re.sub(r"\[.*\]$", "", name)
    else:
        if not _NPM_SPEC.match(spec):
            return None
        head, sep, tail = spec.rpartition("@")
        name, version = (head, tail) if sep and head else (spec, None)
    return name, version if _is_version(version, ecosystem) else None


def _split_image(ref: str) -> tuple[str, str | None] | None:
    """Split a container reference into (registry/repository, tag or digest).

    The tag is after the last `:` only when that `:` follows the last `/`, so a
    registry port (`host:5000/acme/mcp`) is not mistaken for one.
    """
    version: str | None = None
    if "@" in ref:
        ref, _, digest = ref.partition("@")
        version = digest if digest.startswith("sha256:") else None
    else:
        last_slash = ref.rfind("/")
        colon = ref.rfind(":")
        if colon > last_slash:
            ref, version = ref[:colon], ref[colon + 1 :]
            if not _IMAGE_TAG.match(version):
                return None
    parts = ref.split("/")
    registry_like = len(parts) > 1 and (
        "." in parts[0] or ":" in parts[0] or parts[0] == "localhost"
    )
    repo = "/".join(parts[1:]) if registry_like else ref
    if not repo or not _IMAGE_REPO.match(repo):
        return None
    return ref, version if _is_version(version, "docker") else None


def _launch_package(command: str, args: list[str]) -> tuple[str, str, str | None] | None:
    """Return (ecosystem, package, version) a launch command runs, if it names one."""
    exe = Path(command).name.lower()
    argv = [a for a in args if isinstance(a, str)]

    if exe in ("npm", "pnpm", "yarn") and argv and argv[0] in ("exec", "dlx", "x"):
        exe, argv = "npx", argv[1:]
    if exe == "pipx" and argv and argv[0] == "run":
        exe, argv = "uvx", argv[1:]

    if exe in _NPM_LAUNCHERS or exe in _PYPI_LAUNCHERS:
        ecosystem = "npm" if exe in _NPM_LAUNCHERS else "pypi"
        # A flag that selects the package outright: `npx --package pkg bin`,
        # `npx -p pkg bin`, `uvx --from pkg bin`. The positional is then only
        # the executable that package provides.
        selectors = ("--package", "-p") if ecosystem == "npm" else ("--from",)
        for i, arg in enumerate(argv[:-1]):
            if arg in selectors:
                split = _split_version(argv[i + 1], ecosystem)
                return (ecosystem, *split) if split else None
            if arg.startswith(tuple(f"{s}=" for s in selectors if s.startswith("--"))):
                split = _split_version(arg.split("=", 1)[1], ecosystem)
                return (ecosystem, *split) if split else None
        skip = False
        for arg in argv:
            if skip:
                skip = False
                continue
            if arg in _LAUNCHER_VALUE_FLAGS:
                skip = True
                continue
            if arg.startswith("-"):
                continue
            split = _split_version(arg, ecosystem)
            return (ecosystem, *split) if split else None
        return None

    if exe in _CONTAINER_LAUNCHERS:
        if not argv or argv[0] != "run":
            return None
        skip = False
        for arg in argv[1:]:
            if skip:
                skip = False
                continue
            if arg in _CONTAINER_VALUE_FLAGS:
                skip = True
                continue
            if arg.startswith("-"):
                continue
            image = _split_image(arg)
            return ("docker", *image) if image else None
        return None

    return None


def _docker_purl(image: str, version: str | None) -> str:
    # pkg:docker/<namespace>/<name>, with a non-Docker-Hub registry carried as
    # repository_url, per the purl spec.
    parts = image.split("/")
    qualifier = ""
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        qualifier = f"?repository_url={parts[0]}"
        parts = parts[1:]
    purl = "pkg:docker/" + "/".join(parts)
    if version:
        purl += f"@{version}"
    return purl + qualifier


def _package_purl(ecosystem: str, name: str, version: str | None) -> str:
    if ecosystem == "docker":
        return _docker_purl(name, version)
    encoded = name.replace("@", "%40", 1) if name.startswith("@") else name
    purl = f"pkg:{ecosystem}/{encoded}"
    return f"{purl}@{version}" if version else purl


# Token shapes that must never become a component name.
_TOKEN_RE = re.compile(r"(?:sk|pk|ghp|gho|ghs|xox[bpas]|glpat|AKIA)[-_A-Za-z0-9]{12,}")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][\w .:@/\-]{0,63}$")


def _safe_name(name: str | None) -> str | None:
    """A declared server name, or None if it does not look like a name."""
    if not name or not _SAFE_NAME.match(name) or "://" in name or _TOKEN_RE.search(name):
        return None
    return name


def _line_of_key(content: str, key: str) -> int | None:
    m = re.search(r'"' + re.escape(key) + r'"\s*:', content)
    return content[: m.start()].count("\n") + 1 if m else None


def _safe_url(url: str) -> str:
    """Scheme, host and path only. Query strings and userinfo carry tokens."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
    except ValueError:  # an unparseable port: report no URL, keep the server
        return ""
    return f"{parts.scheme}://{host}{parts.path}" if parts.scheme and host else ""


def parse_mcp_config(content: str, path: Path, matcher: Any | None = None) -> Iterator[Finding]:
    """Yield one MCP_SERVER finding per server an MCP client config declares.

    Environment variables and headers are never read into the finding: that is
    where configs keep API keys.

    Args:
        content: Config file content.
        path: File path (relative to scan root).
        matcher: Optional KB Matcher (unscoped), for `match_mcp_identifier`.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning("Invalid JSON in %s: %s", path, e)
        return
    if not isinstance(data, dict):
        return

    servers: dict[str, Any] = {}
    for key in _SERVER_KEYS:
        block = data.get(key)
        if isinstance(block, dict):
            servers.update(block)
    # VS Code user settings nest them under "mcp".
    nested = data.get("mcp")
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        servers.update(nested["servers"])

    for server_name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        command = spec.get("command")
        raw_args = spec.get("args")
        args: list[str] = (
            [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []
        )
        url = spec.get("url") or spec.get("serverUrl")

        package = purl = version = kb_id = None
        ecosystem: str | None = None
        transport: str | None = None
        how: str | None = None

        if isinstance(command, str) and command:
            transport = "stdio"
            # Never the raw arguments: they carry `-e TOKEN=...`, connection
            # strings with passwords and API keys. The program and the package
            # it runs are the provenance; the rest is configuration.
            how = Path(command).name
            launched = _launch_package(command, args)
            if launched:
                ecosystem, package, version = launched
                purl = _package_purl(ecosystem, package, version)
                how = f"{how} {package}" + (f"@{version}" if version else "")
        elif isinstance(url, str) and url:
            declared = str(spec.get("type") or spec.get("transport") or "").lower()
            transport = "sse" if "sse" in declared else "http"
            how = _safe_url(url) or None

        if matcher is not None and package and ecosystem:
            # Identity comes from the package the launcher installs, in that
            # launcher's registry; the KB adds its id, never a different purl.
            kb = matcher.match_mcp_identifier(package, frozenset({ecosystem}))
            if kb:
                kb_id = kb.id

        yield Finding(
            type=FindingType.MCP_SERVER,
            file_path=str(path),
            confidence=1.0,
            line=_line_of_key(content, server_name),
            mcp_info=MCPInfo(
                name=package or _safe_name(server_name) or "mcp-server",
                role="server",
                source="config",
                package=package,
                purl=purl,
                version=version,
                transport=transport,
                kb_id=kb_id,
                how=how,
            ),
        )


# --- source code -----------------------------------------------------------

_PY_SDK_IMPORT = re.compile(
    r"^\s*(?:from\s+(?P<a>mcp|fastmcp|langchain_mcp_adapters|strands\.tools\.mcp)\b[\w.]*\s+import\b"
    r"|import\s+(?P<b>mcp|fastmcp)\b)",
    re.MULTILINE,
)
# A real import or require of an MCP SDK, not merely the string appearing.
_JS_SDK_IMPORT = re.compile(
    r"""(?:\bfrom\s*|^\s*import\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)"""
    r"""["'](?:@modelcontextprotocol/sdk|fastmcp)(?:/[^"']*)?["']""",
    re.MULTILINE,
)

# (regex, role, transport). A server pattern's first group, when present, is
# the server's declared name.
_PY_CONSTRUCTS: list[tuple[re.Pattern[str], str, str | None]] = [
    (re.compile(r"\bFastMCP\(\s*(?:name\s*=\s*)?[\"']([^\"']+)[\"']"), "server", None),
    (re.compile(r"\bFastMCP\(\s*\)"), "server", None),
    (re.compile(r"\bServer\(\s*[\"']([^\"']+)[\"']"), "server", None),
    (re.compile(r"\bstdio_client\(|\bStdioServerParameters\("), "client", "stdio"),
    (re.compile(r"\bsse_client\("), "client", "sse"),
    (re.compile(r"\bstreamablehttp_client\("), "client", "http"),
    (re.compile(r"\bClientSession\("), "client", None),
    (re.compile(r"\bMCPClient\("), "client", None),  # strands.tools.mcp
    (re.compile(r"\bMultiServerMCPClient\("), "client", None),  # langchain-mcp-adapters
    (re.compile(r"\bMCPServerStdio\("), "client", "stdio"),  # openai-agents
    (re.compile(r"\bMCPServer(?:Sse|StreamableHttp)\("), "client", "http"),
]
_JS_CONSTRUCTS: list[tuple[re.Pattern[str], str, str | None]] = [
    (re.compile(r"\bnew\s+(?:Mcp)?Server\(\s*\{\s*name\s*:\s*[\"'`]([^\"'`]+)"), "server", None),
    (re.compile(r"\bnew\s+McpServer\("), "server", None),
    (re.compile(r"\bnew\s+StdioClientTransport\("), "client", "stdio"),
    (re.compile(r"\bnew\s+SSEClientTransport\("), "client", "sse"),
    (re.compile(r"\bnew\s+StreamableHTTPClientTransport\("), "client", "http"),
    (re.compile(r"\bnew\s+Client\("), "client", None),
]

# A launch inside code: `command="npx"` / `command: "uvx"` with its args list.
_CODE_COMMAND = re.compile(r"""\bcommand\s*[=:]\s*["'`](npx|bunx|pnpx|uvx|docker|podman)["'`]""")
_CODE_ARGS = re.compile(r"""\bargs\s*[=:]\s*\[([^\]]*)\]""")
_CODE_STRING = re.compile(r"""["'`]([^"'`]*)["'`]""")


class MCPDetector(BaseDetector):
    """Detect MCP servers and clients built or launched in source code."""

    @property
    def extensions(self) -> frozenset[str]:
        return frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

    def detect(self, content: str, path: Path, matcher: Any | None = None) -> Iterator[Finding]:
        """Yield MCP findings for one file.

        Only a file that imports an MCP SDK is considered at all: `Server(` and
        `new Client(` are everyday names, and a bare string naming a server
        package is just as likely an ordinary import.

        Evidence (`how`) is the construct or the program and package, never the
        source line: lines carry `env={"API_KEY": ...}` and URLs with
        credentials, and an SBOM is passed around.
        """
        is_py = path.suffix.lower() == ".py"
        if not (_PY_SDK_IMPORT if is_py else _JS_SDK_IMPORT).search(content):
            return
        constructs = _PY_CONSTRUCTS if is_py else _JS_CONSTRUCTS

        server_names: set[str] = set()
        server_lines: set[int] = set()
        client_found = False
        for regex, role, transport in constructs:
            # One client finding per file is the useful grain; the transport
            # patterns come first so that one carries a transport.
            if role == "client" and client_found:
                continue
            for m in regex.finditer(content):
                declared = m.group(1) if regex.groups else None
                name = _safe_name(declared)
                line_no = content[: m.start()].count("\n") + 1
                if role == "server":
                    # The unnamed pattern re-matches a named server's line.
                    if (name or "") in server_names or line_no in server_lines:
                        continue
                    server_names.add(name or "")
                    server_lines.add(line_no)
                construct = m.group(0).split("(", 1)[0].strip() + "(...)"
                yield Finding(
                    type=FindingType.MCP_SERVER if role == "server" else FindingType.MCP_CLIENT,
                    file_path=str(path),
                    confidence=0.9,
                    line=line_no,
                    mcp_info=MCPInfo(
                        name=name or ("mcp-server" if role == "server" else "mcp-client"),
                        role=role,
                        source="code",
                        transport=transport,
                        how=construct,
                    ),
                )
                if role == "client":
                    client_found = True
                    break

        # Servers this code launches: the same launcher rules as a config file,
        # applied to a `command=` literal and the `args` list beside it.
        launched: set[str] = set()
        for cm in _CODE_COMMAND.finditer(content):
            window = content[max(0, cm.start() - 400) : cm.end() + 400]
            pos = cm.start() - max(0, cm.start() - 400)
            arg_lists = list(_CODE_ARGS.finditer(window))
            if not arg_lists:
                continue
            nearest = min(arg_lists, key=lambda am: abs(am.start() - pos))
            argv = [sm.group(1) for sm in _CODE_STRING.finditer(nearest.group(1))]
            resolved = _launch_package(cm.group(1), argv)
            if not resolved:
                continue
            ecosystem, package, version = resolved
            if package in launched:
                continue
            launched.add(package)
            kb = None
            scoped = getattr(matcher, "match_mcp_in", None)
            if scoped is not None:
                kb = scoped(package, ecosystem)
            yield Finding(
                type=FindingType.MCP_SERVER,
                file_path=str(path),
                confidence=0.9,
                line=content[: cm.start()].count("\n") + 1,
                mcp_info=MCPInfo(
                    name=package,
                    role="server",
                    source="code",
                    package=package,
                    purl=_package_purl(ecosystem, package, version),
                    version=version,
                    transport="stdio",
                    kb_id=kb.id if kb else None,
                    how=f"{cm.group(1)} {package}" + (f"@{version}" if version else ""),
                ),
            )
