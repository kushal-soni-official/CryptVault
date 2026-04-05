from unittest.mock import patch
from cryptvault.integrations.cve_integration import check_cve

@patch("cryptvault.integrations.cve_integration.requests.get")
def test_check_cve(mock_get):
    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2023-1234",
                            "descriptions": [{"value": "Mock vulnerability"}],
                            "metrics": {
                                "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.5}}]
                            }
                        }
                    }
                ]
            }
            
    mock_get.return_value = MockResponse()
    
    results = check_cve("python", "3.10")
    assert len(results) == 1
    assert results[0]["id"] == "CVE-2023-1234"
    assert results[0]["severity"] == "HIGH"
