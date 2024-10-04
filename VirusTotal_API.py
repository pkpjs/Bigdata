import requests
import time  # time 모듈을 추가합니다.

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"

    def upload_file(self, file_path):
        """파일을 바이러스 토탈에 업로드하고 분석 요청을 보냅니다."""
        url = f"{self.base_url}files"
        headers = {
            "x-apikey": self.api_key
        }
        with open(file_path, "rb") as file:
            response = requests.post(url, headers=headers, files={"file": file})
        return response.json()

    def get_analysis_result(self, resource_id):
        """파일 분석 결과를 가져옵니다."""
        url = f"{self.base_url}analyses/{resource_id}"
        headers = {
            "x-apikey": self.api_key
        }
        response = requests.get(url, headers=headers)
        return response.json()

    def check_hashes_with_virustotal(self, md5_list):
        """MD5 해시 값을 사용하여 바이러스 토탈에서 검사합니다."""
        results = {}
        batch_size = 5  # 한 번에 검사할 해시 개수

        for i in range(0, len(md5_list), batch_size):
            batch = md5_list[i:i + batch_size]
            for md5_hash in batch:
                url = f"{self.base_url}files/{md5_hash}"
                headers = {
                    "x-apikey": self.api_key
                }
                response = requests.get(url, headers=headers)
                results[md5_hash] = response.json()
                print(f"검사 중: {md5_hash}")  # 진행 상황 확인

                # 초당 4개 요청을 위해 0.25초 지연
                time.sleep(0.25)
        return results
