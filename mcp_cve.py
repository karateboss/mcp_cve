from mcp.server.fastmcp import FastMCP
import requests
import logging
import csv
import os

# Configure logging
logging.basicConfig(level=logging.INFO)

mcp = FastMCP(name="cve search tool")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_DETAIL_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0"
NVD_API_KEY = ""  # Optional: Add your NVD API key


def get_headers():
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


@mcp.tool(
    name="search_cve",
    description="Search for CVEs related to a specific vendor and product using the NVD API"
)
def search_cve(vendor: str, product: str) -> dict:
    if not vendor.strip() or not product.strip():
        return {"error": "Both 'vendor' and 'product' must be non-empty."}

    keyword = f"{vendor} {product}"
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    response = requests.get(NVD_API_URL, params=params, headers=get_headers())

    if response.status_code == 429:
        return {"error": "Rate limit exceeded. Please try again later or use an API key."}
    elif response.status_code != 200:
        return {"error": f"Failed to fetch CVEs: {response.status_code} {response.text}"}

    data = response.json()
    results = data.get("vulnerabilities", [])[:5]
    return {
        "vendor": vendor,
        "product": product,
        "total_found": data.get("totalResults", 0),
        "top_results": [format_cve(item.get("cve", {})) for item in results]
    }


@mcp.tool(
    name="get_cve_details",
    description="Fetch detailed information for a specific CVE ID"
)
def get_cve_details(cve_id: str) -> dict:
    if not cve_id.startswith("CVE-"):
        return {"error": "Invalid CVE ID format."}

    response = requests.get(f"{NVD_CVE_DETAIL_URL}/{cve_id}", headers=get_headers())
    if response.status_code != 200:
        return {"error": f"Failed to fetch CVE details: {response.status_code}"}

    cve = response.json().get("result", {}).get("CVE_Items", [{}])[0].get("cve", {})
    return format_cve(cve)


@mcp.tool(
    name="filter_cve_by_severity",
    description="Filter CVEs by severity level for a given vendor and product"
)
def filter_cve_by_severity(vendor: str, product: str, severity: str) -> dict:
    keyword = f"{vendor} {product}"
    params = {
        "keywordSearch": keyword,
        "cvssV3Severity": severity.upper(),
        "resultsPerPage": 5
    }
    response = requests.get(NVD_API_URL, params=params, headers=get_headers())
    if response.status_code != 200:
        return {"error": f"Failed to fetch CVEs: {response.status_code}"}

    data = response.json()
    results = data.get("vulnerabilities", [])
    return {
        "vendor": vendor,
        "product": product,
        "severity_filter": severity.upper(),
        "total_found": data.get("totalResults", 0),
        "top_results": [format_cve(item.get("cve", {})) for item in results]
    }


@mcp.tool(
    name="export_cve_report_csv",
    description="Export CVEs for a vendor/product to CSV"
)
def export_cve_report_csv(vendor: str, product: str) -> dict:
    keyword = f"{vendor} {product}"
    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    response = requests.get(NVD_API_URL, params=params, headers=get_headers())

    if response.status_code != 200:
        return {"error": f"Failed to fetch CVEs: {response.status_code}"}

    data = response.json()
    results = data.get("vulnerabilities", [])

    file_path = f"/mnt/data/{vendor}_{product}_cve_report.csv"
    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["CVE ID", "Summary", "CVSS Score", "Severity", "Vector"])
        for item in results:
            cve = item.get("cve", {})
            formatted = format_cve(cve)
            writer.writerow([
                formatted["id"],
                formatted["summary"],
                formatted["cvss_score"],
                formatted["cvss_severity"],
                formatted["cvss_vector"]
            ])
    return {"file_path": file_path, "message": "CSV report generated successfully."}


def format_cve(cve):
    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
    description_list = cve.get("descriptions", [])
    description = next((d["value"] for d in description_list if d.get("lang") == "en"), "No description available.")
    return {
        "id": cve.get("id"),
        "summary": description,
        "cvss_score": metrics.get("baseScore", "N/A"),
        "cvss_severity": metrics.get("baseSeverity", "N/A"),
        "cvss_vector": metrics.get("vectorString", "N/A")
    }


def main():
    mcp.run()

if __name__ == "__main__":
    main()
