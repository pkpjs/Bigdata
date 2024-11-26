# virustotal_api.py
import requests
import time

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"

    def check_hashes_with_virustotal(self, sha256_list):
        """SHA256 해시 값을 사용하여 바이러스 토탈에서 검사합니다."""
        results = {}
        headers = {"x-apikey": self.api_key}

        for sha256 in sha256_list:
            url = f"{self.base_url}files/{sha256}"
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 429:
                    print("요청 한도를 초과했습니다 (HTTP 429). 15초 후 다시 시도합니다.")
                    time.sleep(15)  # 요청 한도 초과 시 대기
                    response = requests.get(url, headers=headers)  # 재시도
                if response.status_code == 403:
                    print("유효하지 않은 API 키입니다 (HTTP 403).")
                    results["invalid_api_key"] = True
                    break
                elif response.status_code != 200:
                    print(f"해시 조회 실패 ({sha256}): {response.status_code} - {response.text}")
                    results[sha256] = None
                    continue

                results[sha256] = response.json()
                print(f"검사 완료: {sha256}")

                # 초당 4개 요청을 위해 0.25초 지연
                time.sleep(0.25)
            except requests.exceptions.RequestException as e:
                print(f"요청 중 오류 발생 ({sha256}): {e}")
                results[sha256] = None

        return results
