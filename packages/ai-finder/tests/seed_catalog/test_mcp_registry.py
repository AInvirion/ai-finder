"""The MCP Registry importer: what it proposes, and what it refuses."""

from __future__ import annotations

import pytest

from scripts.seed_catalog.mcp_registry import candidate_for, fetch_servers, proposals


def _record(name: str, packages: list[dict], status: str = "active", latest: bool = True):
    return {
        "server": {"name": name, "description": f"{name} server", "packages": packages},
        "_meta": {
            "io.modelcontextprotocol.registry/official": {"status": status, "isLatest": latest}
        },
    }


def test_each_package_type_becomes_a_purl() -> None:
    assert candidate_for({"registryType": "npm", "identifier": "@acme/mcp"}) == (
        "pkg:npm/@acme/mcp",
        ["@acme/mcp"],
    )
    assert candidate_for({"registryType": "pypi", "identifier": "Acme-MCP"}) == (
        "pkg:pypi/acme-mcp",
        ["acme-mcp"],
    )
    assert candidate_for({"registryType": "oci", "identifier": "ghcr.io/acme/mcp:1.2"}) == (
        "pkg:docker/acme/mcp?repository_url=ghcr.io",
        ["ghcr.io/acme/mcp"],
    )
    assert candidate_for({"registryType": "oci", "identifier": "docker.io/acme/mcp"}) == (
        "pkg:docker/acme/mcp",
        ["acme/mcp", "docker.io/acme/mcp"],
    )


def test_out_of_scope_packages_are_not_proposed() -> None:
    assert candidate_for({"registryType": "mcpb", "identifier": "https://x/y.mcpb"}) is None
    assert candidate_for({"registryType": "nuget", "identifier": "Acme.Mcp"}) is None
    # A URL where a package name belongs is not a package.
    assert candidate_for({"registryType": "npm", "identifier": "https://u:pw@h/x.tgz"}) is None


def test_only_active_latest_new_servers() -> None:
    servers = [
        _record("io.acme/live", [{"registryType": "npm", "identifier": "acme-live-mcp"}]),
        _record(
            "io.acme/old", [{"registryType": "npm", "identifier": "acme-old-mcp"}], latest=False
        ),
        _record(
            "io.acme/gone",
            [{"registryType": "npm", "identifier": "acme-gone-mcp"}],
            status="deleted",
        ),
        _record("io.acme/remote", []),
        _record("io.acme/known", [{"registryType": "npm", "identifier": "known-mcp"}]),
    ]
    existing = [{"kind": "mcp_server", "id": "known", "purl": "pkg:npm/known-mcp"}]
    rows = proposals(servers, existing)
    assert [r["purl"] for r in rows] == ["pkg:npm/acme-live-mcp"]
    assert rows[0]["kind"] == "mcp_server" and rows[0]["source"] == "mcp-registry"


def test_a_partial_registry_listing_is_refused() -> None:
    pages = iter([(200, {"servers": [], "metadata": {"nextCursor": "c1"}}), (503, "down")])
    with pytest.raises(RuntimeError, match="partial"):
        fetch_servers(lambda url: next(pages))
    endless = lambda url: (200, {"servers": [], "metadata": {"nextCursor": "again"}})  # noqa: E731
    with pytest.raises(RuntimeError, match="partial"):
        fetch_servers(endless, max_pages=3)
