import requests
import json
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ThreatIntelProvider:
    def __init__(self, cache_file: str = "C:/Major_Project/.intel_cache.json"):
        self.cache_file = cache_file
        self.api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Failed to save intel cache: {e}")

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP against AbuseIPDB. Uses cache if available.
        Fallback to mock data if API key is not present.
        """
        if ip_address in self.cache:
            return self.cache[ip_address]

        if not self.api_key:
            logger.warning(f"No AbuseIPDB API key. Mocking response for {ip_address}")
            # Mock behavior: 8.8.8.8 is clean, others randomly suspicious or not
            score = 0 if ip_address == "8.8.8.8" else (len(ip_address) * 5 % 100)
            mock_result = {
                "ip": ip_address,
                "reputation": "Suspicious" if score > 50 else "Clean",
                "score": score,
                "source": "Mock (No API Key)"
            }
            self.cache[ip_address] = mock_result
            self._save_cache()
            return mock_result

        # Real API Call
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        try:
            response = requests.get(url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result = {
                    "ip": ip_address,
                    "reputation": "Suspicious" if score > 50 else "Clean",
                    "score": score,
                    "country": data.get("countryCode", ""),
                    "domain": data.get("domain", ""),
                    "source": "AbuseIPDB"
                }
                self.cache[ip_address] = result
                self._save_cache()
                return result
            else:
                logger.error(f"AbuseIPDB API error: {response.text}")
                return {"ip": ip_address, "reputation": "Unknown", "score": 0, "error": response.status_code}
        except Exception as e:
            logger.error(f"Failed to contact AbuseIPDB: {e}")
            return {"ip": ip_address, "reputation": "Error", "score": 0, "error": str(e)}

    def enrich_network_df(self, netscan_df):
        """Enriches a whole DataFrame with reputation columns."""
        # Optional helper to enrich pandas DF directly
        if netscan_df is None or netscan_df.empty or 'ForeignAddr' not in netscan_df.columns:
            return netscan_df
            
        scores = []
        reps = []
        for ip in netscan_df['ForeignAddr']:
            res = self.check_ip(str(ip))
            scores.append(res.get("score", 0))
            reps.append(res.get("reputation", "Unknown"))
            
        enriched_df = netscan_df.copy()
        enriched_df['reputation'] = reps
        enriched_df['threat_score'] = scores
        return enriched_df
