from mcp.server.fastmcp import FastMCP
import requests
import logging
import csv
import os

# Configure logging
logging.basicConfig(level=logging.INFO)

mcp = FastMCP(name="cve search tool")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
NVD_API_KEY = os.getenv("NVD_API_KEY")
def get_headers():
    headers = {"User-Agent": "CVE-Search-MCP/1.0"}
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

    # Use more specific CPE matching for better results, sorted by publication date descending
    params = {
        "cpeName": f"cpe:2.3:a:{vendor}:{product}:*",
        "resultsPerPage": 5,
        "startIndex": 0,
        "sortBy": "published",
        "sortOrder": "desc"
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=get_headers(), timeout=30)
        
        # Add debug logging
        logging.info(f"Request URL: {response.url}")
        logging.info(f"Response status: {response.status_code}")
        
        if response.status_code == 429:
            return {"error": "Rate limit exceeded. Please try again later or use an API key."}
        elif response.status_code == 403:
            return {"error": "Access forbidden. API may be blocked or requires authentication."}
        elif response.status_code == 404:
            # Fallback to keyword search if CPE search fails
            return search_cve_fallback(vendor, product)
        elif response.status_code != 200:
            return {"error": f"Failed to fetch CVEs: {response.status_code} {response.text}"}

        data = response.json()
        results = data.get("vulnerabilities", [])[:5]
        
        return {
            "vendor": vendor,
            "product": product,
            "total_found": data.get("totalResults", 0),
            "top_results": [format_cve_v2(item.get("cve", {})) for item in results]
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}


def search_cve_fallback(vendor: str, product: str) -> dict:
    """Fallback search using keyword search instead of CPE, sorted by latest first"""
    params = {
        "keywordSearch": f"{vendor} {product}",
        "resultsPerPage": 5,
        "startIndex": 0,
        "sortBy": "published",
        "sortOrder": "desc"
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=get_headers(), timeout=30)
        
        if response.status_code != 200:
            return {"error": f"Fallback search failed: {response.status_code} {response.text}"}

        data = response.json()
        results = data.get("vulnerabilities", [])[:5]
        
        return {
            "vendor": vendor,
            "product": product,
            "search_method": "keyword_fallback",
            "total_found": data.get("totalResults", 0),
            "top_results": [format_cve_v2(item.get("cve", {})) for item in results]
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Fallback network error: {str(e)}"}


@mcp.tool(
    name="get_cve_details",
    description="Fetch detailed information for a specific CVE ID"
)
def get_cve_details(cve_id: str) -> dict:
    if not cve_id.startswith("CVE-"):
        return {"error": "Invalid CVE ID format. Must start with 'CVE-'"}

    params = {"cveId": cve_id}
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=get_headers(), timeout=30)
        
        logging.info(f"CVE Details Request URL: {response.url}")
        logging.info(f"CVE Details Response status: {response.status_code}")
        
        if response.status_code == 403:
            return {"error": "Access forbidden. API may be blocked or requires authentication."}
        elif response.status_code != 200:
            return {"error": f"Failed to fetch CVE details: {response.status_code} {response.text}"}

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return {"error": f"CVE {cve_id} not found"}
            
        cve = vulnerabilities[0].get("cve", {})
        return format_cve_v2(cve)
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}


@mcp.tool(
    name="filter_cve_by_severity",
    description="Filter CVEs by severity level for a given vendor and product"
)
def filter_cve_by_severity(vendor: str, product: str, severity: str) -> dict:
    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity.upper() not in valid_severities:
        return {"error": f"Invalid severity. Must be one of: {', '.join(valid_severities)}"}

    params = {
        "keywordSearch": f"{vendor} {product}",
        "cvssV3Severity": severity.upper(),
        "resultsPerPage": 5,
        "startIndex": 0,
        "sortBy": "published",
        "sortOrder": "desc"
    }

    try:
        response = requests.get(NVD_API_URL, params=params, headers=get_headers(), timeout=30)
        
        if response.status_code == 403:
            return {"error": "Access forbidden. API may be blocked or requires authentication."}
        elif response.status_code != 200:
            return {"error": f"Failed to fetch CVEs: {response.status_code} {response.text}"}

        data = response.json()
        results = data.get("vulnerabilities", [])
        
        return {
            "vendor": vendor,
            "product": product,
            "severity_filter": severity.upper(),
            "total_found": data.get("totalResults", 0),
            "top_results": [format_cve_v2(item.get("cve", {})) for item in results]
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}


@mcp.tool(
    name="export_cve_report_csv",
    description="Export CVEs for a vendor/product to CSV"
)
def export_cve_report_csv(vendor: str, product: str) -> dict:
    params = {
        "keywordSearch": f"{vendor} {product}",
        "resultsPerPage": 20,
        "startIndex": 0,
        "sortBy": "published",
        "sortOrder": "desc"
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=get_headers(), timeout=30)

        if response.status_code != 200:
            return {"error": f"Failed to fetch CVEs: {response.status_code}"}

        data = response.json()
        results = data.get("vulnerabilities", [])

        # Use allowed directory
        file_path = f"/Users/david/PDFs/{vendor}_{product}_cve_report.csv"
        
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["CVE ID", "Summary", "CVSS Score", "Severity", "Vector", "Published", "Modified"])
            
            for item in results:
                cve = item.get("cve", {})
                formatted = format_cve_v2(cve)
                writer.writerow([
                    formatted["id"],
                    formatted["summary"][:100] + "..." if len(formatted["summary"]) > 100 else formatted["summary"],
                    formatted["cvss_score"],
                    formatted["cvss_severity"],
                    formatted["cvss_vector"],
                    formatted["published"],
                    formatted["modified"]
                ])
                
        return {
            "file_path": file_path, 
            "message": f"CSV report generated successfully with {len(results)} CVEs.",
            "total_cves": len(results)
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        return {"error": f"File operation error: {str(e)}"}


def format_cve_v2(cve):
    """Format CVE data for NVD API 2.0 response structure"""
    if not cve:
        return {
            "id": "N/A",
            "summary": "No CVE data available",
            "cvss_score": "N/A",
            "cvss_severity": "N/A", 
            "cvss_vector": "N/A",
            "published": "N/A",
            "modified": "N/A"
        }
    
    # Extract CVSS metrics (try v3.1 first, then v3.0, then v2.0)
    metrics_v31 = cve.get("metrics", {}).get("cvssMetricV31", [])
    metrics_v30 = cve.get("metrics", {}).get("cvssMetricV30", [])
    metrics_v2 = cve.get("metrics", {}).get("cvssMetricV2", [])
    
    cvss_score = "N/A"
    cvss_severity = "N/A"
    cvss_vector = "N/A"
    
    if metrics_v31:
        cvss_data = metrics_v31[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", "N/A")
        cvss_severity = cvss_data.get("baseSeverity", "N/A")
        cvss_vector = cvss_data.get("vectorString", "N/A")
    elif metrics_v30:
        cvss_data = metrics_v30[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", "N/A")
        cvss_severity = cvss_data.get("baseSeverity", "N/A")
        cvss_vector = cvss_data.get("vectorString", "N/A")
    elif metrics_v2:
        cvss_data = metrics_v2[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", "N/A")
        cvss_severity = cvss_data.get("baseSeverity", "N/A")
        cvss_vector = cvss_data.get("vectorString", "N/A")
    
    # Extract description
    descriptions = cve.get("descriptions", [])
    description = "No description available."
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "No description available.")
            break
    
    return {
        "id": cve.get("id", "N/A"),
        "summary": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "published": cve.get("published", "N/A"),
        "modified": cve.get("lastModified", "N/A")
    }


def main():
    mcp.run()

if __name__ == "__main__":
    main()
