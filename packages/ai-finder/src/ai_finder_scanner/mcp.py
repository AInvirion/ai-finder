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


def _split_version(spec: str, ecosystem: str) -> tuple[str, str | None]:
    """Split `pkg@1.2.3` / `@scope/pkg@1` (npm) or `pkg==1.2` / `pkg@1.2` (pypi).

    A dist-tag such as `@latest` is dropped rather than reported: it names
    whatever was newest on the day the launcher ran, not a version.
    """
    name, version = spec, None
    if ecosystem == "pypi":
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+?)(?:==|@)([\w.\-+]+)$", spec)
        if m:
            name, version = m.group(1), m.group(2)
    else:
        head, sep, tail = spec.rpartition("@")
        if sep and head and "/" not in tail:
            name, version = head, tail or None
    if version and not version[0].isdigit():
        version = None
    return name, version


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
        skip = False
        for arg in argv:
            if skip:
                skip = False
                continue
            if arg in _LAUNCHER_VALUE_FLAGS:
                # `uvx --from pkg cmd` runs pkg, not cmd.
                if arg == "--from" and ecosystem == "pypi":
                    idx = argv.index(arg)
                    if idx + 1 < len(argv):
                        name, version = _split_version(argv[idx + 1], ecosystem)
                        return ecosystem, name, version
                skip = True
                continue
            if arg.startswith("-"):
                continue
            name, version = _split_version(arg, ecosystem)
            return ecosystem, name, version
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
            image, _, tag = arg.partition(":") if "@" not in arg else (arg, "", "")
            return "docker", image, tag or None
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


_URL_RE = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s\"'`]+", re.IGNORECASE)
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)((?:[\w-]*(?:token|key|secret|password|passwd|auth)[\w-]*)\s*[=:]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,)\]}]+)"
)
_TOKEN_RE = re.compile(r"\b(?:sk|pk|ghp|gho|ghs|xox[bpas]|glpat|AKIA)[-_A-Za-z0-9]{12,}\b")


def _redact(text: str) -> str:
    """Strip what a source line may carry that must not land in an SBOM."""
    text = _URL_RE.sub(lambda m: _safe_url(m.group(0)) or "<url>", text)
    text = _SECRET_ASSIGN_RE.sub(lambda m: m.group(1) + "***", text)
    return _TOKEN_RE.sub("***", text)


def _line_of_key(content: str, key: str) -> int | None:
    m = re.search(r'"' + re.escape(key) + r'"\s*:', content)
    return content[: m.start()].count("\n") + 1 if m else None


def _safe_url(url: str) -> str:
    """Scheme, host and path only. Query strings and userinfo carry tokens."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
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

        if matcher is not None:
            for candidate in (package, how):
                if not candidate:
                    continue
                kb = matcher.match_mcp_identifier(candidate)
                if kb:
                    kb_id = kb.id
                    if purl is None and kb.purl:
                        purl = kb.purl
                    break

        yield Finding(
            type=FindingType.MCP_SERVER,
            file_path=str(path),
            confidence=1.0,
            line=_line_of_key(content, server_name),
            mcp_info=MCPInfo(
                name=package or server_name,
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
_JS_SDK_IMPORT = re.compile(r"""["'](?:@modelcontextprotocol/sdk|fastmcp)(?:/[^"']*)?["']""")

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

# A string literal that could be a package name a launcher runs.
_STRING_LITERAL = re.compile(r"""["'`](@?[A-Za-z0-9][\w.\-]*(?:/[\w.\-]+)?(?:@[\w.\-]+)?)["'`]""")


class MCPDetector(BaseDetector):
    """Detect MCP servers and clients built or launched in source code."""

    @property
    def extensions(self) -> frozenset[str]:
        return frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

    def detect(self, content: str, path: Path, matcher: Any | None = None) -> Iterator[Finding]:
        """Yield MCP findings for one file.

        Constructs are only trusted in a file that imports an MCP SDK: `Server(`
        and `new Client(` are common names. Launched server packages are matched
        against the KB in any file, since the KB entry is the evidence.
        """
        is_py = path.suffix.lower() == ".py"
        imports = (_PY_SDK_IMPORT if is_py else _JS_SDK_IMPORT).search(content)
        constructs = _PY_CONSTRUCTS if is_py else _JS_CONSTRUCTS

        if imports:
            lines = content.splitlines()
            server_names: set[str] = set()
            server_lines: set[int] = set()
            client_found = False
            for regex, role, transport in constructs:
                # One client finding per file is the useful grain; the transport
                # patterns come first so that one carries a transport.
                if role == "client" and client_found:
                    continue
                for m in regex.finditer(content):
                    name = m.group(1) if regex.groups else None
                    line_no = content[: m.start()].count("\n") + 1
                    if role == "server":
                        # The unnamed pattern re-matches a named server's line.
                        if (name or "") in server_names or line_no in server_lines:
                            continue
                        server_names.add(name or "")
                        server_lines.add(line_no)
                    line = lines[line_no - 1].strip() if line_no <= len(lines) else ""
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
                            how=_redact(line)[:200],
                        ),
                    )
                    if role == "client":
                        client_found = True
                        break

        resolve = getattr(matcher, "match_mcp_any", None)
        if resolve is None:
            return
        launched: set[str] = set()
        for m in _STRING_LITERAL.finditer(content):
            literal = m.group(1)
            name, version = _split_version(literal, "npm")
            kb = resolve(name)
            if kb is None or kb.id in launched:
                continue
            launched.add(kb.id)
            line_no = content[: m.start()].count("\n") + 1
            yield Finding(
                type=FindingType.MCP_SERVER,
                file_path=str(path),
                confidence=0.9,
                line=line_no,
                mcp_info=MCPInfo(
                    name=name,
                    role="server",
                    source="code",
                    package=name,
                    purl=kb.purl,
                    version=version,
                    kb_id=kb.id,
                    how=_redact(content.splitlines()[line_no - 1].strip())[:200],
                ),
            )
