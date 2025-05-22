# -*- coding: utf-8 -*-
from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP(name="cve search tool")

@mcp.tool(
    name="search_cve",
    description="Search for CVEs related to a specific vendor and product"
)
def search_cve(vendor: str, product: str) -> dict:
    """
    Search for CVEs related to a specific vendor and product.

    Example: vendor="microsoft", product="windows_10"
    """
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    response = requests.get(url)

    if response.status_code != 200:
        return {"error": f"Failed to fetch CVEs: {response.status_code}"}

    data = response.json()
    results = data.get("data", [])[:5]

    return {
        "vendor": vendor,
        "product": product,
        "total_found": len(data.get("data", [])),
        "top_results": [
            {
                "id": item.get("id"),
                "summary": item.get("summary"),
                "cvss": item.get("cvss")
            } for item in results
        ]
    }

# Run the MCP server
def main():
    mcp.run()

if __name__ == "__main__":
    main()
