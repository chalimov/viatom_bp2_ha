"""
Test Viatom Cloud API — run on your PC to check if the cloud API is live.

This tests the documented API at cloud.viatomtech.com using your
ViHealth app credentials (email + password).

Usage:
    pip install requests
    python tools/test_cloud_api.py
"""

import requests
import json
import sys

# Known API base URLs to try (the API may have moved)
API_BASES = [
    "https://cloud.viatomtech.com",
    "https://api.viatomtech.com",
    "https://cloud.viatomtech.com.cn",
    "https://api.viatomtech.com.cn",
    "http://cloud.viatomtech.com",
]

def test_api():
    print("=== Viatom Cloud API Test ===\n")

    email = input("Enter your ViHealth app email: ").strip()
    password = input("Enter your ViHealth app password: ").strip()

    if not email or not password:
        print("Email and password required!")
        return

    # Try each base URL
    for base in API_BASES:
        print(f"\n--- Testing {base} ---")

        # Test 1: GET /search/patient (list patients)
        url = f"{base}/search/patient"
        print(f"  GET {url}")
        try:
            resp = requests.get(
                url,
                auth=(email, password),
                timeout=10,
                headers={"Accept": "application/json"},
            )
            print(f"  Status: {resp.status_code}")
            if resp.status_code == 200:
                print(f"  Response: {resp.text[:500]}")
                try:
                    data = resp.json()
                except json.JSONDecodeError:
                    print(f"  Response (not JSON): {resp.text[:300]}")
                    continue

                print(f"  Parsed: {json.dumps(data, indent=2)[:1000]}")

                # If we got patients, try to get observations for the first one
                if isinstance(data, list) and len(data) > 0:
                    patient_id = data[0].get("patient_id")
                    if patient_id:
                        print(f"\n  Found patient_id={patient_id}, querying observations...")
                        obs_url = f"{base}/search/{patient_id}/observation"
                        obs_resp = requests.get(
                            obs_url,
                            auth=(email, password),
                            timeout=10,
                            headers={"Accept": "application/json"},
                        )
                        print(f"  GET {obs_url} → {obs_resp.status_code}")
                        if obs_resp.status_code == 200:
                            obs_data = obs_resp.json()
                            print(f"  Observations: {json.dumps(obs_data, indent=2)[:2000]}")

                            # Get first observation detail
                            if isinstance(obs_data, list) and len(obs_data) > 0:
                                obs_id = obs_data[0].get("observation_id")
                                if obs_id:
                                    detail_url = f"{base}/observation/{obs_id}"
                                    detail_resp = requests.get(
                                        detail_url,
                                        auth=(email, password),
                                        timeout=10,
                                        headers={"Accept": "application/json"},
                                    )
                                    print(f"\n  GET {detail_url} → {detail_resp.status_code}")
                                    if detail_resp.status_code == 200:
                                        print(f"  Detail: {json.dumps(detail_resp.json(), indent=2)[:3000]}")

                print(f"\n  SUCCESS with {base}!")
                return  # Found working base URL
            elif resp.status_code == 401:
                print("  Auth failed — credentials may be wrong, but server is alive!")
            elif resp.status_code == 404:
                print("  404 — endpoint not found at this base URL")
            else:
                print(f"  Response: {resp.text[:300]}")
        except requests.exceptions.ConnectionError as e:
            print(f"  Connection failed: {e}")
        except requests.exceptions.Timeout:
            print("  Timeout after 10s")
        except Exception as e:
            print(f"  Error: {e}")

    print("\n--- Additional test: check if ViHealth uses a different API ---")
    # The newer ViHealth app might use a different API
    alt_urls = [
        "https://open.viatomtech.com",
        "https://vihealth.viatomtech.com",
        "https://api.vihealth.com",
    ]
    for url in alt_urls:
        try:
            resp = requests.get(url, timeout=5)
            print(f"  {url} → {resp.status_code}")
        except Exception as e:
            print(f"  {url} → {type(e).__name__}")

    print("\nDone. If none worked, we may need to intercept the ViHealth app traffic.")


if __name__ == "__main__":
    test_api()
