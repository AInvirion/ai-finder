"""SDK and MCP identification against the KB's identifier lists, end to end.

The KB has always carried SDK and MCP identifiers (several names per package,
like models), but the scanner never handed its matcher to the detectors and
never read an MCP config, so none of it reached the SBOM. These tests use the
real seed JSONs, not hand-written rows, so a seed edit that drops an
identifier fails here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from ai_finder_cli.main import main
from ai_finder_kb.database import Database
from ai_finder_kb.matcher import Matcher
from ai_finder_scanner.detectors.javascript import JavaScriptDetector
from ai_finder_scanner.detectors.tools import ToolsDetector
from ai_finder_scanner.mcp import MCPDetector, parse_mcp_config
from ai_finder_scanner.models import FindingType
from ai_finder_scanner.output.cyclonedx import CycloneDXFormatter
from ai_finder_scanner.scanner import Scanner
from click.testing import CliRunner

SEED_DIR = Path(__file__).parents[2] / "src" / "ai_finder_kb" / "seed"


@pytest.fixture
def seed_kb(tmp_path: Path) -> Path:
    """A KB holding the real seed SDK and MCP rows (models left out: slow, unused)."""
    db_path = tmp_path / "kb.db"
    with Database(db_path) as db:
        db.initialize()
        for row in json.loads((SEED_DIR / "sdks.json").read_text()):
            db.execute(
                "INSERT INTO sdks (id, purl, patterns, category, license) VALUES (?, ?, ?, ?, ?)",
                (
                    row["id"],
                    row["purl"],
                    json.dumps(row["patterns"]),
                    row.get("category"),
                    row.get("license"),
                ),
            )
        for row in json.loads((SEED_DIR / "mcp_servers.json").read_text()):
            db.execute(
                "INSERT INTO mcp_servers (id, purl, patterns, description) VALUES (?, ?, ?, ?)",
                (row["id"], row["purl"], json.dumps(row["patterns"]), row.get("description")),
            )
        db.commit()
    return db_path


@pytest.fixture
def matcher(seed_kb: Path):
    db = Database(seed_kb)
    db.connect()
    yield Matcher(db)
    db.close()


def _write(root: Path, rel: str, text: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


# --- matcher -----------------------------------------------------------------


class TestIdentifierMatching:
    def test_import_name_resolves_to_its_package(self, matcher) -> None:
        # `import strands` ships as strands-agents; the PyPI package literally
        # named `strands` is an unrelated physics library.
        match = matcher.match_sdk_identifier("strands.agent", frozenset({"pypi"}))
        assert match is not None
        assert match.purl == "pkg:pypi/strands-agents"

    def test_whole_segment_only(self, matcher) -> None:
        pypi = frozenset({"pypi"})
        # Substring matching would answer `openai` for langchain_openai and
        # `torch` for torchvision.
        assert matcher.match_sdk_identifier("langchain_openai", pypi).id != "openai"
        torchvision = matcher.match_sdk_identifier("torchvision", pypi)
        assert torchvision is None or torchvision.id != "torch"
        assert matcher.match_sdk_identifier("torch.nn", pypi).id == "torch"

    def test_ecosystem_scoping(self, matcher) -> None:
        assert matcher.match_sdk_identifier("openai", frozenset({"pypi"})).purl == (
            "pkg:pypi/openai"
        )
        assert matcher.match_sdk_identifier("openai", frozenset({"npm"})).purl == "pkg:npm/openai"

    def test_mcp_sdks_are_catalogued(self, matcher) -> None:
        assert matcher.match_sdk_identifier("mcp.server.fastmcp", frozenset({"pypi"})).purl == (
            "pkg:pypi/mcp"
        )
        js = matcher.match_sdk_identifier("@modelcontextprotocol/sdk/client/index.js", None)
        assert js is not None and js.purl == "pkg:npm/@modelcontextprotocol/sdk"


# --- MCP config --------------------------------------------------------------


class TestMCPConfig:
    def test_each_launcher_names_its_package(self, matcher) -> None:
        config = {
            "mcpServers": {
                "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
                "fetch": {"command": "uvx", "args": ["mcp-server-fetch==0.6.2"]},
                "docker-gh": {
                    "command": "docker",
                    "args": [
                        "run",
                        "-i",
                        "--rm",
                        "-e",
                        "TOKEN",
                        "ghcr.io/github/github-mcp-server",
                    ],
                },
                "pinned": {"command": "npx", "args": ["@acme/thing@2.1.0"]},
                "floating": {"command": "npx", "args": ["@acme/other@latest"]},
            }
        }
        findings = list(parse_mcp_config(json.dumps(config), Path(".mcp.json"), matcher))
        by_name = {f.mcp_info.name: f.mcp_info for f in findings}

        assert all(f.type == FindingType.MCP_SERVER for f in findings)
        assert by_name["@modelcontextprotocol/server-github"].kb_id == "mcp-github"
        assert by_name["mcp-server-fetch"].purl == "pkg:pypi/mcp-server-fetch@0.6.2"
        # The image, not the value of -e.
        docker = by_name["ghcr.io/github/github-mcp-server"]
        assert docker.kb_id == "github-mcp-server"
        assert docker.purl.startswith("pkg:docker/github/github-mcp-server")
        # Not in the KB, still a server: the config is the evidence.
        assert by_name["@acme/thing"].version == "2.1.0"
        assert by_name["@acme/thing"].kb_id is None
        # A dist-tag is not a version.
        assert by_name["@acme/other"].version is None

    def test_secrets_never_reach_the_finding(self, matcher) -> None:
        config = {
            "servers": {
                "remote": {"type": "http", "url": "https://u:pw@mcp.example.com/v1?token=SEKRET"},
                "local": {"command": "npx", "args": ["x-mcp"], "env": {"API_KEY": "SEKRET"}},
            }
        }
        findings = list(parse_mcp_config(json.dumps(config), Path("mcp.json"), matcher))
        assert len(findings) == 2
        assert "SEKRET" not in repr(findings)
        assert "pw" not in repr([f.mcp_info.how for f in findings])
        remote = next(f.mcp_info for f in findings if f.mcp_info.name == "remote")
        assert remote.how == "https://mcp.example.com/v1"
        assert remote.transport == "http"


# --- MCP in code -------------------------------------------------------------


class TestMCPCode:
    def test_python_server_and_client(self, matcher) -> None:
        src = (
            "from mcp.server.fastmcp import FastMCP\n"
            "from mcp.client.stdio import stdio_client\n"
            'mcp = FastMCP("weather")\n'
            "async def go(p):\n"
            "    async with stdio_client(p) as s: ...\n"
        )
        findings = list(MCPDetector().detect(src, Path("srv.py"), matcher.scoped({"pypi"})))
        servers = [f for f in findings if f.type == FindingType.MCP_SERVER]
        clients = [f for f in findings if f.type == FindingType.MCP_CLIENT]
        assert [s.mcp_info.name for s in servers] == ["weather"]
        assert servers[0].line == 3
        assert len(clients) == 1 and clients[0].mcp_info.transport == "stdio"

    def test_constructor_names_need_an_mcp_import(self) -> None:
        # `Server(` and `new Client(` are everyday names.
        src = 'from http.server import Server\nsrv = Server("web")\n'
        assert list(MCPDetector().detect(src, Path("web.py"))) == []

    def test_launched_server_resolved_across_ecosystems(self, matcher) -> None:
        # Python code spawning an npm server.
        src = (
            "from mcp import StdioServerParameters\n"
            'p = StdioServerParameters(command="npx", '
            'args=["-y", "@modelcontextprotocol/server-memory"])\n'
        )
        findings = list(MCPDetector().detect(src, Path("c.py"), matcher.scoped({"pypi"})))
        launched = [f.mcp_info for f in findings if f.mcp_info.kb_id]
        assert [m.kb_id for m in launched] == ["mcp-memory"]
        assert launched[0].purl == "pkg:npm/@modelcontextprotocol/server-memory"

    def test_typescript_server(self) -> None:
        src = (
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            'const s = new McpServer({ name: "notes", version: "1.0.0" });\n'
        )
        findings = list(MCPDetector().detect(src, Path("s.ts")))
        assert [f.mcp_info.name for f in findings] == ["notes"]


# --- regressions found scanning a real project -------------------------------


class TestRegressions:
    def test_js_import_with_a_dotted_subpath(self) -> None:
        # The MCP SDK is only importable by subpath; `[@\w/-]+` refused the dot
        # and the whole import was missed.
        src = 'import {\n  Client,\n} from "@modelcontextprotocol/sdk/client/index.js";\n'
        findings = list(JavaScriptDetector().detect(src, Path("c.ts")))
        assert [f.sdk_usage.sdk for f in findings] == ["@modelcontextprotocol/sdk"]

    def test_tool_named_by_its_function(self) -> None:
        src = (
            "@tool\ndef search_web(q: str) -> str:\n    ...\n\n"
            "@tool\nasync def fetch(u):\n    ...\n"
        )
        names = [f.tool_info.name for f in ToolsDetector().detect(src, Path("t.py"))]
        assert names == ["search_web", "fetch"]


# --- the customer path: CLI scan to SBOM ---------------------------------------


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    _write(
        root,
        ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "gh": {"command": "npx", "args": ["@modelcontextprotocol/server-github"]}
                }
            }
        ),
    )
    _write(
        root,
        ".vscode/mcp.json",
        json.dumps({"servers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}}),
    )
    _write(root, "app/agent.py", "from strands import Agent\nfrom openai import OpenAI\n")
    _write(root, "requirements.txt", "strands-agents>=1.25.0\nopenai==1.60.0\nmcp==1.2.0\n")
    _write(root, "web/package.json", json.dumps({"dependencies": {"openai": "^4.0.0"}}))
    _write(root, "web/index.ts", 'import OpenAI from "openai";\n')
    return root


def _cyclonedx(project: Path, kb: Path) -> dict:
    result = CliRunner().invoke(
        main,
        ["--no-telemetry", "scan", "-q", "--no-enrich", "-f", "cyclonedx"]
        + ["--kb-path", str(kb), str(project)],
    )
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


class TestSBOM:
    def test_mcp_servers_from_both_config_locations(self, project: Path, seed_kb: Path) -> None:
        bom = _cyclonedx(project, seed_kb)
        purls = {c.get("purl") for c in bom["components"]}
        assert "pkg:npm/modelcontextprotocol/server-github" in purls
        assert "pkg:pypi/mcp-server-fetch" in purls
        gh = next(c for c in bom["components"] if c["name"].endswith("server-github"))
        props = {p["name"]: p["value"] for p in gh["properties"]}
        assert props["ai-finder:mcp:role"] == "server"
        assert props["ai-finder:mcp:source"] == "config"
        assert gh["evidence"]["occurrences"][0]["location"] == ".mcp.json"

    def test_import_and_manifest_are_one_component_with_both_locations(
        self, project: Path, seed_kb: Path
    ) -> None:
        bom = _cyclonedx(project, seed_kb)
        # Packages only: the agent built with it is its own component.
        strands = [c for c in bom["components"] if "strands" in c.get("purl", "")]
        # One component, named for the package, not the import.
        assert [c["name"] for c in strands] == ["strands-agents"]
        locations = {o["location"] for o in strands[0]["evidence"]["occurrences"]}
        assert locations == {"app/agent.py", "requirements.txt"}
        how = {o.get("additionalContext") for o in strands[0]["evidence"]["occurrences"]}
        assert "from strands import Agent" in how

    def test_same_name_in_two_registries_stays_two(self, project: Path, seed_kb: Path) -> None:
        bom = _cyclonedx(project, seed_kb)
        openai = sorted(c["purl"] for c in bom["components"] if c["name"] == "openai")
        assert openai == ["pkg:npm/openai@4.0.0", "pkg:pypi/openai@1.60.0"]
        refs = [c["bom-ref"] for c in bom["components"]]
        assert len(refs) == len(set(refs))


def test_scanner_without_kb_still_detects_mcp_sdk(tmp_path: Path) -> None:
    # The built-in lists remain the floor when no KB is available.
    _write(tmp_path, "s.py", "from mcp.server.fastmcp import FastMCP\n")
    result = Scanner(detect_licenses=False).scan(tmp_path)
    assert [f.sdk_usage.sdk for f in result.findings if f.sdk_usage] == ["mcp"]
    assert CycloneDXFormatter().format(result)
