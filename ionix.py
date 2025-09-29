from typing import Any
import httpx
import os
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

mcp = FastMCP("ionix")

IONIX_API_BASE = "https://api.portal.ionix.io/api/v1/"
ACCOUNT_NAME = os.getenv("IONIX_ACCOUNT_NAME")
api_key = os.getenv("IONIX_API_KEY")

def fetch(
    path: str,
    params: dict[str, Any] | None = None,
    account_name: str | None = None,
):
    print(f"Fetching data from {path}")
    with httpx.Client() as client:
        try:
            # Use provided account name or fall back to environment variable
            effective_account_name = account_name or ACCOUNT_NAME

            headers = {
                "X-Account-Name": effective_account_name,
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
            }

            url = f"{IONIX_API_BASE}{path}"

            # Filter out None values from params
            if params:
                params = {k: v for k, v in params.items() if v is not None}

            response = client.get(url, headers=headers, params=params, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

# Discovery endpoints
@mcp.tool()
async def get_discovery_org_assets(
    asset: str | None = None,
    asset_contains: str | None = None,
    importance_in: str | None = None,
    risk_score_in: str | None = None,
    technologies_contains: str | None = None,
    group: str | None = None,
    # HTTPS/HTTP filtering
    https_title: str | None = None,
    https_title_contains: str | None = None,
    https_status_code_in: str | None = None,
    http_title: str | None = None,
    http_title_contains: str | None = None,
    http_status_code_in: str | None = None,
    # Network and Infrastructure
    ip: str | None = None,
    ips_contains: str | None = None,
    hosting_provider_contains: str | None = None,
    geo_contains: str | None = None,
    open_ports_overlap: str | None = None,
    # Security and Risk
    cves_contains: str | None = None,
    confidence_level_in: str | None = None,
    maintenance_grade_in: str | None = None,
    waf_contains: str | None = None,
    # Asset Classification
    type_in: str | None = None,
    is_parked_domain: bool | None = None,
    is_web_accessible: bool | None = None,
    tags_contains: str | None = None,
    # Date-based filtering
    first_seen_gte: str | None = None,
    first_seen_lte: str | None = None,
    domain_expiration_date_gte: str | None = None,
    domain_expiration_date_lte: str | None = None,
    # Domain and Registration
    registrar_contains: str | None = None,
    registrant_organization_contains: str | None = None,
    whois_emails_contains: str | None = None,
    # Standard parameters
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get organization assets from the discovery inventory with comprehensive filtering options.

    Args:
        asset: Exact asset name to filter by (optional)
        asset_contains: Filter assets containing this string (optional)
        importance_in: Filter by importance levels, comma-separated (optional)
        risk_score_in: Filter by risk score levels, comma-separated (optional)
        technologies_contains: Filter by technologies containing this string (optional)
        group: Filter by asset group (optional)

        # HTTPS/HTTP Filtering
        https_title: Exact HTTPS page title (optional)
        https_title_contains: Filter by HTTPS page title containing this string (optional)
        https_status_code_in: Filter by HTTPS status codes, comma-separated (e.g., "200,301,404") (optional)
        http_title: Exact HTTP page title (optional)
        http_title_contains: Filter by HTTP page title containing this string (optional)
        http_status_code_in: Filter by HTTP status codes, comma-separated (e.g., "200,301,404") (optional)

        # Network and Infrastructure
        ip: Exact IP address (optional)
        ips_contains: Filter by IP addresses containing this string (optional)
        hosting_provider_contains: Filter by hosting provider containing this string (optional)
        geo_contains: Filter by geographic location containing this string (optional)
        open_ports_overlap: Filter by assets with these open ports, comma-separated (optional)

        # Security and Risk
        cves_contains: Filter by CVE vulnerabilities containing this string (optional)
        confidence_level_in: Filter by confidence levels, comma-separated (optional)
        maintenance_grade_in: Filter by maintenance grades, comma-separated (optional)
        waf_contains: Filter by WAF (Web Application Firewall) containing this string (optional)

        # Asset Classification
        type_in: Filter by asset types, comma-separated (optional)
        is_parked_domain: Filter for parked domains (True/False) (optional)
        is_web_accessible: Filter for web accessible assets (True/False) (optional)
        tags_contains: Filter by tags containing this string (optional)

        # Date-based Filtering
        first_seen_gte: Filter assets first seen on or after this date (YYYY-MM-DD) (optional)
        first_seen_lte: Filter assets first seen on or before this date (YYYY-MM-DD) (optional)
        domain_expiration_date_gte: Filter domains expiring on or after this date (YYYY-MM-DD) (optional)
        domain_expiration_date_lte: Filter domains expiring on or before this date (YYYY-MM-DD) (optional)

        # Domain and Registration
        registrar_contains: Filter by domain registrar containing this string (optional)
        registrant_organization_contains: Filter by registrant organization containing this string (optional)
        whois_emails_contains: Filter by WHOIS emails containing this string (optional)

        # Standard Parameters
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    # Basic asset filtering
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if importance_in is not None:
        params["importance__in"] = importance_in
    if risk_score_in is not None:
        params["risk_score__in"] = risk_score_in
    if technologies_contains is not None:
        params["technologies__contains"] = technologies_contains
    if group is not None:
        params["group"] = group

    # HTTPS/HTTP filtering
    if https_title is not None:
        params["https_title"] = https_title
    if https_title_contains is not None:
        params["https_title__contains"] = https_title_contains
    if https_status_code_in is not None:
        params["https_status_code__in"] = https_status_code_in
    if http_title is not None:
        params["http_title"] = http_title
    if http_title_contains is not None:
        params["http_title__contains"] = http_title_contains
    if http_status_code_in is not None:
        params["http_status_code__in"] = http_status_code_in

    # Network and Infrastructure
    if ip is not None:
        params["ip"] = ip
    if ips_contains is not None:
        params["ips__contains"] = ips_contains
    if hosting_provider_contains is not None:
        params["hosting_provider__contains"] = hosting_provider_contains
    if geo_contains is not None:
        params["geo__contains"] = geo_contains
    if open_ports_overlap is not None:
        params["open_ports__overlap"] = open_ports_overlap

    # Security and Risk
    if cves_contains is not None:
        params["cves__contains"] = cves_contains
    if confidence_level_in is not None:
        params["confidence_level__in"] = confidence_level_in
    if maintenance_grade_in is not None:
        params["maintenance_grade__in"] = maintenance_grade_in
    if waf_contains is not None:
        params["waf__contains"] = waf_contains

    # Asset Classification
    if type_in is not None:
        params["type__in"] = type_in
    if is_parked_domain is not None:
        params["is_parked_domain"] = is_parked_domain
    if is_web_accessible is not None:
        params["is_web_accessible"] = is_web_accessible
    if tags_contains is not None:
        params["tags__contains"] = tags_contains

    # Date-based filtering
    if first_seen_gte is not None:
        params["first_seen__gte"] = first_seen_gte
    if first_seen_lte is not None:
        params["first_seen__lte"] = first_seen_lte
    if domain_expiration_date_gte is not None:
        params["domain_expiration_date__gte"] = domain_expiration_date_gte
    if domain_expiration_date_lte is not None:
        params["domain_expiration_date__lte"] = domain_expiration_date_lte

    # Domain and Registration
    if registrar_contains is not None:
        params["registrar__contains"] = registrar_contains
    if registrant_organization_contains is not None:
        params["registrant_organization__contains"] = registrant_organization_contains
    if whois_emails_contains is not None:
        params["whois_emails__contains"] = whois_emails_contains

    # Standard parameters
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("discovery/org-assets/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_discovery_certificates(
    asset: str | None = None,
    issuer_contains: str | None = None,
    subject_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get SSL certificates from the discovery inventory.

    Args:
        asset: Filter by asset name (optional)
        issuer_contains: Filter certificates by issuer containing this string (optional)
        subject_contains: Filter certificates by subject containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if issuer_contains is not None:
        params["issuer__contains"] = issuer_contains
    if subject_contains is not None:
        params["subject__contains"] = subject_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("discovery/certificates/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_discovery_connections(
    asset: str | None = None,
    connection_type: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get asset connections from the discovery inventory.

    Args:
        asset: Filter by asset name (optional)
        connection_type: Filter by connection type (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if connection_type is not None:
        params["connection_type"] = connection_type
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("discovery/connections/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_discovery_technologies(
    asset_contains: str | None = None,
    technology_contains: str | None = None,
    version_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get technologies discovered on assets.

    Args:
        asset_contains: Filter by assets containing this string (optional)
        technology_contains: Filter by technology containing this string (optional)
        version_contains: Filter by version containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if technology_contains is not None:
        params["technology__contains"] = technology_contains
    if version_contains is not None:
        params["version__contains"] = version_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("discovery/technologies/", params=params, account_name=account_name)
    return str(data)

# Assessment endpoints
@mcp.tool()
async def get_attack_surface_risk_score(
    subsidiary: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get attack surface risk scores for the organization.

    Args:
        subsidiary: Filter by subsidiary name (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if subsidiary is not None:
        params["subsidiary"] = subsidiary
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("assessments/attack-surface-risk-score/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_attack_surface_risk_score_details(
    category_in: str | None = None,
    title_contains: str | None = None,
    subsidiary: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get detailed attack surface risk score information.

    Args:
        category_in: Filter by category, comma-separated values (optional)
        title_contains: Filter by title containing this string (optional)
        subsidiary: Filter by subsidiary name (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if category_in is not None:
        params["category__in"] = category_in
    if title_contains is not None:
        params["title__contains"] = title_contains
    if subsidiary is not None:
        params["subsidiary"] = subsidiary
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("assessments/attack-surface-risk-score/details/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_attack_surface_risk_score_issues(
    asset: str | None = None,
    asset_contains: str | None = None,
    category_in: str | None = None,
    title_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get issues contributing to attack surface risk scores.

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)
        category_in: Filter by category, comma-separated values (optional)
        title_contains: Filter by title containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if category_in is not None:
        params["category__in"] = category_in
    if title_contains is not None:
        params["title__contains"] = title_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("assessments/attack-surface-risk-score/issues/", params=params, account_name=account_name)
    return str(data)

# Remediation endpoints
@mcp.tool()
async def get_action_items_open(
    asset: str | None = None,
    asset_contains: str | None = None,
    title_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get open action items for remediation.

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)
        title_contains: Filter by title containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if title_contains is not None:
        params["title__contains"] = title_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("remediation/action-items/open/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_action_items_open_detailed(
    asset: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get detailed open action items for remediation.

    Args:
        asset: Filter by exact asset name (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("remediation/action-items/open/detailed/", params=params, account_name=account_name)
    return str(data)

# Dashboard endpoints
@mcp.tool()
async def get_dashboard_geomap(
    limit: int | None = None,
    offset: int | None = None,
    account_name: str | None = None
) -> str:
    """Get geographic map data for the dashboard.

    Args:
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset

    data = fetch("dashboard/geomap/", params=params, account_name=account_name)
    return str(data)

# Tests endpoint
@mcp.tool()
async def get_tests(
    asset: str | None = None,
    test_type: str | None = None,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get security test results.

    Args:
        asset: Filter by asset name (optional)
        test_type: Filter by test type (optional)
        status: Filter by test status (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if test_type is not None:
        params["test_type"] = test_type
    if status is not None:
        params["status"] = status
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("tests/", params=params, account_name=account_name)
    return str(data)

# Additional discovery endpoints
@mcp.tool()
async def get_discovery_logins(
    asset: str | None = None,
    asset_contains: str | None = None,
    username_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get login assets from the discovery inventory.

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)
        username_contains: Filter by usernames containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if username_contains is not None:
        params["username__contains"] = username_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("discovery/logins/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_discovery_managed_domains(
    domain: str | None = None,
    domain_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get managed domains from the discovery inventory.

    Args:
        domain: Filter by exact domain name (optional)
        domain_contains: Filter by domains containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if domain is not None:
        params["domain"] = domain
    if domain_contains is not None:
        params["domain__contains"] = domain_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("discovery/managed-domains/", params=params, account_name=account_name)
    return str(data)

# Additional remediation endpoints
@mcp.tool()
async def get_action_items_closed(
    asset: str | None = None,
    asset_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get closed action items.

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("remediation/action-items/closed/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_action_items_all(
    asset: str | None = None,
    asset_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get all action items (open and closed).

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("remediation/action-items/all/", params=params, account_name=account_name)
    return str(data)

# Assessment endpoints for digital supply chain
@mcp.tool()
async def get_assessments_digital_supply_chain(
    asset: str | None = None,
    asset_contains: str | None = None,
    technologies_contains: str | None = None,
    risk_score_in: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get external assets from the digital supply chain assessment.

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)
        technologies_contains: Filter by technologies containing this string (optional)
        risk_score_in: Filter by risk score levels, comma-separated (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if technologies_contains is not None:
        params["technologies__contains"] = technologies_contains
    if risk_score_in is not None:
        params["risk_score__in"] = risk_score_in
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("assessments/digital-supply-chain/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_assessments_org_assets(
    asset: str | None = None,
    asset_contains: str | None = None,
    importance_in: str | None = None,
    risk_score_in: str | None = None,
    technologies_contains: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get organization assets from the assessments page.

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)
        importance_in: Filter by importance levels, comma-separated (optional)
        risk_score_in: Filter by risk score levels, comma-separated (optional)
        technologies_contains: Filter by technologies containing this string (optional)
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        search: Search term to filter results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset
    if asset_contains is not None:
        params["asset__contains"] = asset_contains
    if importance_in is not None:
        params["importance__in"] = importance_in
    if risk_score_in is not None:
        params["risk_score__in"] = risk_score_in
    if technologies_contains is not None:
        params["technologies__contains"] = technologies_contains
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if search is not None:
        params["search"] = search
    if ordering is not None:
        params["ordering"] = ordering

    data = fetch("assessments/org-assets/", params=params, account_name=account_name)
    return str(data)

def main():
    """Main entry point for the IONIX MCP server."""
    api_key = os.getenv("IONIX_API_KEY")
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()
