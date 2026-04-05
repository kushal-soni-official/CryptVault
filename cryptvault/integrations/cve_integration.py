import requests
from typing import List, Dict

# The free NIST NVD API 2.0 without an API key allows 5 requests per 30 seconds.
# We will do a simple check prioritizing keywords.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def check_cve(software: str, version: str) -> List[Dict]:
    """Check NIST NVD for known vulnerabilities for a specific software and version."""
    query = f"{software} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 5 # Limit to top 5 for fast parsing
    }
    
    headers = {
        "User-Agent": "CryptVault-CVE-Checker"
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            results = []
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cvss_data = {}
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    
                results.append({
                    "id": cve.get("id", "Unknown"),
                    "description": cve.get("descriptions", [{"value": "No description found"}])[0].get("value"),
                    "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                    "score": cvss_data.get("baseScore", 0.0)
                })
            return results
        else:
            return [{"error": f"API request failed with status {response.status_code}. Rate limit exceeded or invalid request."}]
    except requests.exceptions.RequestException as e:
        return [{"error": f"Connection error: {str(e)}"}]
