import threading

def check_hashes(vt_api, sha256_list):
    """SHA256 해시를 사용하여 바이러스 토탈에서 검사합니다."""
    vt_results = vt_api.check_hashes_with_virustotal(sha256_list)

    # 결과 출력
    for sha256_hash, result in vt_results.items():
        if 'error' in result:
            print(f"SHA256: {sha256_hash}, 오류: {result['error']['message']}")
        else:
            print(f"SHA256: {sha256_hash}, 검사 결과: {result}")
