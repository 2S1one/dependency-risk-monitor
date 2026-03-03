import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
RESOURCES_DIR = Path(__file__).parent / "resources"

mcp = FastMCP("dependency-risk-monitor")

# ── Resources ──────────────────────────────────────────────────────────────

@mcp.resource("org://config")
def get_org_config() -> str:
    """Organization config: critical repos, severity threshold, max age."""
    return (RESOURCES_DIR / "config.json").read_text()


@mcp.resource("org://exceptions")
def get_org_exceptions() -> str:
    """Known exceptions — CVEs that should not block the pipeline."""
    return (RESOURCES_DIR / "exceptions.json").read_text()


# ── Tools ──────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_repositories(org: str) -> str:
    """List repositories of a GitHub organization."""
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/orgs/{org}/repos",
            headers=headers,
            params={"per_page": 100, "sort": "pushed"},
        )
        resp.raise_for_status()
        repos = resp.json()

    result = [
        {
            "name": r["name"],
            "default_branch": r["default_branch"],
            "topics": r.get("topics", []),
            "pushed_at": r["pushed_at"],
        }
        for r in repos
    ]
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_dependencies(owner: str, repo: str) -> str:
    """Fetch repository dependencies via GitHub Dependency Graph SBOM API."""
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom",
            headers=headers,
        )
        resp.raise_for_status()
        sbom = resp.json()

    packages = sbom.get("sbom", {}).get("packages", [])
    dependencies = []
    for pkg in packages:
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        purl = pkg.get("externalRefs", [{}])[0].get("referenceLocator", "")
        if name and version and purl:
            dependencies.append({"name": name, "version": version, "purl": purl})

    return json.dumps(dependencies, indent=2)


@mcp.tool()
async def check_vulnerabilities(dependencies: list[dict]) -> str:
    """Check dependencies for vulnerabilities via OSV.dev batch API.

    Args:
        dependencies: list of dicts with fields 'name', 'version', 'purl'
    """
    queries = [{"package": {"purl": dep["purl"]}} for dep in dependencies if dep.get("purl")]
    if not queries:
        return json.dumps([])

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": queries},
        )
        resp.raise_for_status()
        data = resp.json()

    results = []
    for dep, result in zip(dependencies, data.get("results", [])):
        vulns = result.get("vulns", [])
        if not vulns:
            continue
        for vuln in vulns:
            severity = _extract_severity(vuln)
            fixed_version = _extract_fixed_version(vuln)
            results.append(
                {
                    "purl": dep["purl"],
                    "package": dep["name"],
                    "version": dep["version"],
                    "cve": vuln.get("id", "UNKNOWN"),
                    "severity": severity,
                    "summary": vuln.get("summary", ""),
                    "fixed_version": fixed_version,
                }
            )

    results = [r for r in results if r["severity"] == "CRITICAL"]

    return json.dumps(results, indent=2)


@mcp.tool()
async def create_github_issue(owner: str, repo: str, title: str, body: str) -> str:
    """Create a GitHub Issue with a vulnerability report.

    Returns:
        URL of the created issue
    """
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "title": title,
        "body": body,
        "labels": ["security", "dependencies"],
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues",
            headers=headers,
            json=payload,
        )
        resp.raise_for_status()
        issue = resp.json()

    return json.dumps({"url": issue["html_url"], "number": issue["number"]})


# ── Helpers ────────────────────────────────────────────────────────────────

def _extract_severity(vuln: dict) -> str:
    """Extract the highest severity from CVSSv3 score or database_specific field."""
    for severity_entry in vuln.get("severity", []):
        if severity_entry.get("type") == "CVSS_V3":
            score_str = severity_entry.get("score", "")
            return _cvss_score_to_label(score_str)
    db_specific = vuln.get("database_specific", {})
    return db_specific.get("severity", "UNKNOWN").upper()


def _cvss_score_to_label(score: str) -> str:
    """Convert CVSS vector string to a severity label."""
    try:
        parts = score.split("/")
        base = float(parts[-1]) if len(parts) == 1 else float(parts[1].split(":")[1])
    except (ValueError, IndexError):
        return "UNKNOWN"
    if base >= 9.0:
        return "CRITICAL"
    if base >= 7.0:
        return "HIGH"
    if base >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_fixed_version(vuln: dict) -> str:
    """Find the fixed version from affected[].ranges."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return "unknown"


if __name__ == "__main__":
    mcp.run()
