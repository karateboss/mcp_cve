# -*- coding: utf-8 -*-
from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP(name="cve search tool")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = ""  # Optional: Add your NVD API key for better rate limits

@mcp.tool(
    name="search_cve",
    description="Search for CVEs related to a specific vendor and product using the NVD API"
)
def search_cve(vendor: str, product: str) -> dict:
    """
    Search for CVEs related to a specific vendor and product via the NVD API.

    Example: vendor="microsoft", product="windows 10"
    """
    keyword = f"{vendor} {product}"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    response = requests.get(NVD_API_URL, params=params, headers=headers)

    if response.status_code != 200:
        return {"error": f"Failed to fetch CVEs: {response.status_code} {response.text}"}

    data = response.json()
    results = data.get("vulnerabilities", [])[:5]

    return {
        "vendor": vendor,
        "product": product,
        "total_found": data.get("totalResults", 0),
        "top_results": [
            {
                "id": item.get("cve", {}).get("id"),
                "summary": item.get("cve", {}).get("descriptions", [{}])[0].get("value", ""),
                "cvss": item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            } for item in results
        ]
    }

# Run the MCP server
def main():
    mcp.run()

if __name__ == "__main__":
    main()
