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
    # Urgency/Severity filtering
    urgency_in: str | None = None,
    # Time filtering - open/creation time
    first_opened_at_gte: str | None = None,
    first_opened_at_lte: str | None = None,
    first_opened_at_range: str | None = None,
    last_opened_at_gte: str | None = None,
    last_opened_at_lte: str | None = None,
    last_opened_at_range: str | None = None,
    # Time filtering - close time
    last_closed_at_gte: str | None = None,
    last_closed_at_lte: str | None = None,
    last_closed_at_range: str | None = None,
    # Standard parameters
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

        # Urgency/Severity Filtering
        urgency_in: Filter by urgency/severity levels, comma-separated (optional)

        # Time Filtering - Open/Creation Time
        first_opened_at_gte: Filter items first opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_lte: Filter items first opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_range: Filter items first opened within datetime range, comma-separated (optional)
        last_opened_at_gte: Filter items last opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_lte: Filter items last opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_range: Filter items last opened within datetime range, comma-separated (optional)

        # Time Filtering - Close Time
        last_closed_at_gte: Filter items closed on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_lte: Filter items closed on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_range: Filter items closed within datetime range, comma-separated (optional)

        # Standard Parameters
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

    # Urgency/Severity filtering
    if urgency_in is not None:
        params["urgency__in"] = urgency_in

    # Time filtering - open/creation time
    if first_opened_at_gte is not None:
        params["first_opened_at__gte"] = first_opened_at_gte
    if first_opened_at_lte is not None:
        params["first_opened_at__lte"] = first_opened_at_lte
    if first_opened_at_range is not None:
        params["first_opened_at__range"] = first_opened_at_range
    if last_opened_at_gte is not None:
        params["last_opened_at__gte"] = last_opened_at_gte
    if last_opened_at_lte is not None:
        params["last_opened_at__lte"] = last_opened_at_lte
    if last_opened_at_range is not None:
        params["last_opened_at__range"] = last_opened_at_range

    # Time filtering - close time
    if last_closed_at_gte is not None:
        params["last_closed_at__gte"] = last_closed_at_gte
    if last_closed_at_lte is not None:
        params["last_closed_at__lte"] = last_closed_at_lte
    if last_closed_at_range is not None:
        params["last_closed_at__range"] = last_closed_at_range

    # Standard parameters
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
    # Urgency/Severity filtering
    urgency_in: str | None = None,
    # Time filtering - open/creation time
    first_opened_at_gte: str | None = None,
    first_opened_at_lte: str | None = None,
    first_opened_at_range: str | None = None,
    last_opened_at_gte: str | None = None,
    last_opened_at_lte: str | None = None,
    last_opened_at_range: str | None = None,
    # Time filtering - close time
    last_closed_at_gte: str | None = None,
    last_closed_at_lte: str | None = None,
    last_closed_at_range: str | None = None,
    # Standard parameters
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get detailed open action items for remediation.

    Args:
        asset: Filter by exact asset name (optional)

        # Urgency/Severity Filtering
        urgency_in: Filter by urgency/severity levels, comma-separated (optional)

        # Time Filtering - Open/Creation Time
        first_opened_at_gte: Filter items first opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_lte: Filter items first opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_range: Filter items first opened within datetime range, comma-separated (optional)
        last_opened_at_gte: Filter items last opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_lte: Filter items last opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_range: Filter items last opened within datetime range, comma-separated (optional)

        # Time Filtering - Close Time
        last_closed_at_gte: Filter items closed on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_lte: Filter items closed on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_range: Filter items closed within datetime range, comma-separated (optional)

        # Standard Parameters
        limit: Number of results to return per page (optional)
        offset: The initial index from which to return the results (optional)
        ordering: Field to use for ordering results (optional)
        account_name: Override the default account name from environment (optional)
    """
    params = {}
    if asset is not None:
        params["asset"] = asset

    # Urgency/Severity filtering
    if urgency_in is not None:
        params["urgency__in"] = urgency_in

    # Time filtering - open/creation time
    if first_opened_at_gte is not None:
        params["first_opened_at__gte"] = first_opened_at_gte
    if first_opened_at_lte is not None:
        params["first_opened_at__lte"] = first_opened_at_lte
    if first_opened_at_range is not None:
        params["first_opened_at__range"] = first_opened_at_range
    if last_opened_at_gte is not None:
        params["last_opened_at__gte"] = last_opened_at_gte
    if last_opened_at_lte is not None:
        params["last_opened_at__lte"] = last_opened_at_lte
    if last_opened_at_range is not None:
        params["last_opened_at__range"] = last_opened_at_range

    # Time filtering - close time
    if last_closed_at_gte is not None:
        params["last_closed_at__gte"] = last_closed_at_gte
    if last_closed_at_lte is not None:
        params["last_closed_at__lte"] = last_closed_at_lte
    if last_closed_at_range is not None:
        params["last_closed_at__range"] = last_closed_at_range

    # Standard parameters
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
    # Urgency/Severity filtering
    urgency_in: str | None = None,
    # Time filtering - open/creation time
    first_opened_at_gte: str | None = None,
    first_opened_at_lte: str | None = None,
    first_opened_at_range: str | None = None,
    last_opened_at_gte: str | None = None,
    last_opened_at_lte: str | None = None,
    last_opened_at_range: str | None = None,
    # Time filtering - close time
    last_closed_at_gte: str | None = None,
    last_closed_at_lte: str | None = None,
    last_closed_at_range: str | None = None,
    # Standard parameters
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get closed action items.

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)

        # Urgency/Severity Filtering
        urgency_in: Filter by urgency/severity levels, comma-separated (optional)

        # Time Filtering - Open/Creation Time
        first_opened_at_gte: Filter items first opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_lte: Filter items first opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_range: Filter items first opened within datetime range, comma-separated (optional)
        last_opened_at_gte: Filter items last opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_lte: Filter items last opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_range: Filter items last opened within datetime range, comma-separated (optional)

        # Time Filtering - Close Time
        last_closed_at_gte: Filter items closed on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_lte: Filter items closed on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_range: Filter items closed within datetime range, comma-separated (optional)

        # Standard Parameters
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

    # Urgency/Severity filtering
    if urgency_in is not None:
        params["urgency__in"] = urgency_in

    # Time filtering - open/creation time
    if first_opened_at_gte is not None:
        params["first_opened_at__gte"] = first_opened_at_gte
    if first_opened_at_lte is not None:
        params["first_opened_at__lte"] = first_opened_at_lte
    if first_opened_at_range is not None:
        params["first_opened_at__range"] = first_opened_at_range
    if last_opened_at_gte is not None:
        params["last_opened_at__gte"] = last_opened_at_gte
    if last_opened_at_lte is not None:
        params["last_opened_at__lte"] = last_opened_at_lte
    if last_opened_at_range is not None:
        params["last_opened_at__range"] = last_opened_at_range

    # Time filtering - close time
    if last_closed_at_gte is not None:
        params["last_closed_at__gte"] = last_closed_at_gte
    if last_closed_at_lte is not None:
        params["last_closed_at__lte"] = last_closed_at_lte
    if last_closed_at_range is not None:
        params["last_closed_at__range"] = last_closed_at_range

    # Standard parameters
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
    # Urgency/Severity filtering
    urgency_in: str | None = None,
    # Time filtering - open/creation time
    first_opened_at_gte: str | None = None,
    first_opened_at_lte: str | None = None,
    first_opened_at_range: str | None = None,
    last_opened_at_gte: str | None = None,
    last_opened_at_lte: str | None = None,
    last_opened_at_range: str | None = None,
    # Time filtering - close time
    last_closed_at_gte: str | None = None,
    last_closed_at_lte: str | None = None,
    last_closed_at_range: str | None = None,
    # Standard parameters
    limit: int | None = None,
    offset: int | None = None,
    ordering: str | None = None,
    account_name: str | None = None
) -> str:
    """Get all action items (open and closed).

    Args:
        asset: Filter by exact asset name (optional)
        asset_contains: Filter by assets containing this string (optional)

        # Urgency/Severity Filtering
        urgency_in: Filter by urgency/severity levels, comma-separated (optional)

        # Time Filtering - Open/Creation Time
        first_opened_at_gte: Filter items first opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_lte: Filter items first opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        first_opened_at_range: Filter items first opened within datetime range, comma-separated (optional)
        last_opened_at_gte: Filter items last opened on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_lte: Filter items last opened on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_opened_at_range: Filter items last opened within datetime range, comma-separated (optional)

        # Time Filtering - Close Time
        last_closed_at_gte: Filter items closed on or after this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_lte: Filter items closed on or before this datetime (YYYY-MM-DDTHH:MM:SS) (optional)
        last_closed_at_range: Filter items closed within datetime range, comma-separated (optional)

        # Standard Parameters
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

    # Urgency/Severity filtering
    if urgency_in is not None:
        params["urgency__in"] = urgency_in

    # Time filtering - open/creation time
    if first_opened_at_gte is not None:
        params["first_opened_at__gte"] = first_opened_at_gte
    if first_opened_at_lte is not None:
        params["first_opened_at__lte"] = first_opened_at_lte
    if first_opened_at_range is not None:
        params["first_opened_at__range"] = first_opened_at_range
    if last_opened_at_gte is not None:
        params["last_opened_at__gte"] = last_opened_at_gte
    if last_opened_at_lte is not None:
        params["last_opened_at__lte"] = last_opened_at_lte
    if last_opened_at_range is not None:
        params["last_opened_at__range"] = last_opened_at_range

    # Time filtering - close time
    if last_closed_at_gte is not None:
        params["last_closed_at__gte"] = last_closed_at_gte
    if last_closed_at_lte is not None:
        params["last_closed_at__lte"] = last_closed_at_lte
    if last_closed_at_range is not None:
        params["last_closed_at__range"] = last_closed_at_range

    # Standard parameters
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

# MSSP endpoints
@mcp.tool()
async def get_mssp_company(
    account_name: str | None = None
) -> str:
    """Get MSSP company information.

    Returns MSSP company details for the authenticated API key.

    Args:
        account_name: Override the default account name from environment (optional)
    """
    data = fetch("mssp/mssp-company/", account_name=account_name)
    return str(data)

@mcp.tool()
async def list_mssp_sub_accounts(
    display_name: str | None = None,
    display_name_contains: str | None = None,
    display_name_contains_ne: str | None = None,
    display_name_endswith: str | None = None,
    display_name_icontains: str | None = None,
    display_name_intext: str | None = None,
    display_name_ne: str | None = None,
    display_name_startswith: str | None = None,
    id_in: str | None = None,
    is_active_plan: bool | None = None,
    last_login_date_gte: str | None = None,
    last_login_date_lte: str | None = None,
    last_login_date_range: str | None = None,
    last_scan_date_gte: str | None = None,
    last_scan_date_lte: str | None = None,
    last_scan_date_range: str | None = None,
    last_seed_data_update_time_gte: str | None = None,
    last_seed_data_update_time_lte: str | None = None,
    last_seed_data_update_time_range: str | None = None,
    mssp_company: str | None = None,
    mssp_company_contains: str | None = None,
    mssp_company_contains_ne: str | None = None,
    mssp_company_endswith: str | None = None,
    mssp_company_ne: str | None = None,
    mssp_company_startswith: str | None = None,
    name: str | None = None,
    name_contains: str | None = None,
    name_contains_ne: str | None = None,
    name_endswith: str | None = None,
    name_icontains: str | None = None,
    name_intext: str | None = None,
    name_ne: str | None = None,
    name_startswith: str | None = None,
    plan_in: str | None = None,
    risk_score_in: str | None = None,
    scan_frequency_in: str | int | None = None,
    scan_status_in: str | None = None,
    tags_contains: str | None = None,
    tags_contains_ne: str | None = None,
    tags_in: str | None = None,
    tags_isnull: bool | None = None,
    tags_overlap: str | None = None,
    tags_overlap_ne: str | None = None,
    ordering: str | None = None,
    search: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    fields: str | None = None,
    account_name: str | None = None,
) -> str:
    """List MSSP sub-accounts with rich filtering.

    Filters mirror the IONIX API query parameters for `/mssp/sub-account/`.

    Args:
        display_name: Exact display name
        display_name_contains: Display name contains
        display_name_contains_ne: Display name contains (negated)
        display_name_endswith: Display name endswith
        display_name_icontains: Display name case-insensitive contains
        display_name_intext: Display name full-text search
        display_name_ne: Display name not equal
        display_name_startswith: Display name startswith
        id_in: Comma-separated list of IDs
        is_active_plan: Whether account has an active plan
        last_login_date_gte: Last login date >= (YYYY-MM-DD)
        last_login_date_lte: Last login date <= (YYYY-MM-DD)
        last_login_date_range: Date range, comma-separated
        last_scan_date_gte: Last scan date >= (YYYY-MM-DD)
        last_scan_date_lte: Last scan date <= (YYYY-MM-DD)
        last_scan_date_range: Date range, comma-separated
        last_seed_data_update_time_gte: Last seed update >= (YYYY-MM-DD)
        last_seed_data_update_time_lte: Last seed update <= (YYYY-MM-DD)
        last_seed_data_update_time_range: Date range, comma-separated
        mssp_company: Exact MSSP company name
        mssp_company_contains: MSSP company contains
        mssp_company_contains_ne: MSSP company contains (negated)
        mssp_company_endswith: MSSP company endswith
        mssp_company_ne: MSSP company not equal
        mssp_company_startswith: MSSP company startswith
        name: Exact company name
        name_contains: Company name contains
        name_contains_ne: Company name contains (negated)
        name_endswith: Company name endswith
        name_icontains: Company name case-insensitive contains
        name_intext: Company name full-text search
        name_ne: Company name not equal
        name_startswith: Company name startswith
        plan_in: Comma-separated plan values. Valid options:
            - Silver
            - Gold
            - Platinum
            - Trial
            - Inactive
        risk_score_in: Comma-separated risk scores
        scan_frequency_in: Comma-separated scan frequencies. Valid options:
            - 1000 (Daily option 0)
            - 1001 (Daily option 1)
            - 1002 (Daily option 2)
            - 2000 (Weekly)
            - 2001 (BiWeekly)
            - 3000 (Monthly)
            - 3001 (Quarterly)
        scan_status_in: Comma-separated scan statuses
        tags_contains: Tags contains
        tags_contains_ne: Tags contains (negated)
        tags_in: Comma-separated tags
        tags_isnull: Whether tags is null
        tags_overlap: Comma-separated tags to overlap
        tags_overlap_ne: Comma-separated tags that must not overlap
        ordering: Field for ordering
        search: Search term
        limit: Page size
        offset: Result offset
        fields: Comma-separated fields to include
        account_name: Override default account
    """
    params: dict[str, Any] = {}

    if display_name is not None:
        params["display_name"] = display_name
    if display_name_contains is not None:
        params["display_name__contains"] = display_name_contains
    if display_name_contains_ne is not None:
        params["display_name__contains_ne"] = display_name_contains_ne
    if display_name_endswith is not None:
        params["display_name__endswith"] = display_name_endswith
    if display_name_icontains is not None:
        params["display_name__icontains"] = display_name_icontains
    if display_name_intext is not None:
        params["display_name__intext"] = display_name_intext
    if display_name_ne is not None:
        params["display_name__ne"] = display_name_ne
    if display_name_startswith is not None:
        params["display_name__startswith"] = display_name_startswith
    if id_in is not None:
        params["id__in"] = id_in
    if is_active_plan is not None:
        params["is_active_plan"] = is_active_plan
    if last_login_date_gte is not None:
        params["last_login_date__gte"] = last_login_date_gte
    if last_login_date_lte is not None:
        params["last_login_date__lte"] = last_login_date_lte
    if last_login_date_range is not None:
        params["last_login_date__range"] = last_login_date_range
    if last_scan_date_gte is not None:
        params["last_scan_date__gte"] = last_scan_date_gte
    if last_scan_date_lte is not None:
        params["last_scan_date__lte"] = last_scan_date_lte
    if last_scan_date_range is not None:
        params["last_scan_date__range"] = last_scan_date_range
    if last_seed_data_update_time_gte is not None:
        params["last_seed_data_update_time__gte"] = last_seed_data_update_time_gte
    if last_seed_data_update_time_lte is not None:
        params["last_seed_data_update_time__lte"] = last_seed_data_update_time_lte
    if last_seed_data_update_time_range is not None:
        params["last_seed_data_update_time__range"] = last_seed_data_update_time_range
    if mssp_company is not None:
        params["mssp_company"] = mssp_company
    if mssp_company_contains is not None:
        params["mssp_company__contains"] = mssp_company_contains
    if mssp_company_contains_ne is not None:
        params["mssp_company__contains_ne"] = mssp_company_contains_ne
    if mssp_company_endswith is not None:
        params["mssp_company__endswith"] = mssp_company_endswith
    if mssp_company_ne is not None:
        params["mssp_company__ne"] = mssp_company_ne
    if mssp_company_startswith is not None:
        params["mssp_company__startswith"] = mssp_company_startswith
    if name is not None:
        params["name"] = name
    if name_contains is not None:
        params["name__contains"] = name_contains
    if name_contains_ne is not None:
        params["name__contains_ne"] = name_contains_ne
    if name_endswith is not None:
        params["name__endswith"] = name_endswith
    if name_icontains is not None:
        params["name__icontains"] = name_icontains
    if name_intext is not None:
        params["name__intext"] = name_intext
    if name_ne is not None:
        params["name__ne"] = name_ne
    if name_startswith is not None:
        params["name__startswith"] = name_startswith
    if plan_in is not None:
        params["plan__in"] = plan_in
    if risk_score_in is not None:
        params["risk_score__in"] = risk_score_in
    if scan_frequency_in is not None:
        params["scan_frequency__in"] = scan_frequency_in
    if scan_status_in is not None:
        params["scan_status__in"] = scan_status_in
    if tags_contains is not None:
        params["tags__contains"] = tags_contains
    if tags_contains_ne is not None:
        params["tags__contains_ne"] = tags_contains_ne
    if tags_in is not None:
        params["tags__in"] = tags_in
    if tags_isnull is not None:
        params["tags__isnull"] = tags_isnull
    if tags_overlap is not None:
        params["tags__overlap"] = tags_overlap
    if tags_overlap_ne is not None:
        params["tags__overlap_ne"] = tags_overlap_ne
    if ordering is not None:
        params["ordering"] = ordering
    if search is not None:
        params["search"] = search
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if fields is not None:
        params["fields"] = fields

    data = fetch("mssp/sub-account/", params=params, account_name=account_name)
    return str(data)

@mcp.tool()
async def get_mssp_sub_account(
    company_name: str,
    account_name: str | None = None
) -> str:
    """Get a single MSSP sub-account by company name.

    Args:
        company_name: The sub-account company name (path parameter)
        account_name: Override the default account name from environment (optional)
    """
    path = f"mssp/sub-account/{company_name}/"
    data = fetch(path, account_name=account_name)
    return str(data)

def main():
    """Main entry point for the IONIX MCP server."""
    api_key = os.getenv("IONIX_API_KEY")
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()
