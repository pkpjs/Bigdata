import pandas as pd
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from data_selection import create_file_selector
from VirusTotal_API import VirusTotalAPI
from hash_checker import check_hashes
import threading
import random
import time
from config import API_KEY
from plot_results import plot_results  # 그래프 파일에서 함수 가져오기


if __name__ == "__main__":
    api_key = API_KEY

    normal_file, malware_file = create_file_selector()
    ngram_file = 'ngram (1).csv'

    data_loader = DataLoader(normal_file, malware_file, ngram_file)
    pe_all = data_loader.load_data(load_malware=malware_file is not None)

    if pe_all.empty:
        print("데이터가 비어 있습니다. 파일 경로를 확인하세요.")
        exit()

    pe_all = pe_all.loc[:, ~pe_all.columns.duplicated()]
    pe_all.reset_index(drop=True, inplace=True)

    preprocessor = DataPreprocessor(pe_all)
    preprocessor.filter_na()
    preprocessor.drop_columns(['filename', 'MD5', 'packer_type'])
    X, Y = preprocessor.get_features_and_labels()

    X = preprocessor.remove_constant_features(X)

    feature_selector = FeatureSelector(X, Y)
    X = feature_selector.select_features()

    classifier = Classifiers(X, Y)
    results = {
        'svm': classifier.do_svm(),
        'randomforest': classifier.do_randomforest(),
        'naivebayes': classifier.do_naivebayes(),
        'dnn': classifier.do_dnn(epochs=10)
    }

    print("모델 평가 결과:")
    malicious_counts = {}
    for model, (accuracy, predictions) in results.items():
        print(f"{model} 정확도: {accuracy:.4f}")

        count_malicious = (predictions == 1).sum()
        count_benign = (predictions == 0).sum()

        print(f"악성 파일 개수: {count_malicious}, 정상 파일 개수: {count_benign}\n")

        malicious_counts[model] = count_malicious

    max_malicious_count = max(malicious_counts.values())
    best_models = [model for model, count in malicious_counts.items() if count == max_malicious_count]

    selected_model = best_models[0]
    print(f"선택된 모델: {selected_model} (악성 파일 개수: {max_malicious_count})")

    pe_all['class'] = Y
    if 'MD5' in pe_all.columns:
        malicious_md5 = pe_all.loc[pe_all['class'] == 1, 'MD5']
        print("악성 파일의 MD5 해시 값:")
        md5_list = malicious_md5.tolist()

        if len(md5_list) > 10:
            selected_md5_list = random.sample(md5_list, 10)
        else:
            selected_md5_list = md5_list

        vt_api = VirusTotalAPI(api_key)

        # VirusTotal API 쓰레드 시작
        thread = threading.Thread(target=check_hashes, args=(vt_api, selected_md5_list))
        thread.start()

        # MD5 해시 확인하는 동안 대기
        for md5_hash in selected_md5_list:
            time.sleep(0.25)

        # 쓰레드가 끝날 때까지 대기
        thread.join()

        print("바이러스 토탈 API 결과 확인이 완료되었습니다.")

    else:
        print("MD5 칼럼이 데이터프레임에 없습니다.")

    # 모든 작업이 완료된 후 그래프 출력
    plot_results(results, malicious_counts)
