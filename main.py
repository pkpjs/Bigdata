import pandas as pd
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from data_selection import create_file_selector  # 파일 선택 모듈 가져오기

if __name__ == "__main__":
    # 파일 선택 UI 호출
    normal_file, malware_file = create_file_selector()  # 사용자 입력에서 파일 경로 가져오기
    ngram_file = 'ngram (1).csv'

    data_loader = DataLoader(normal_file, malware_file, ngram_file)
    pe_all = data_loader.load_data(load_malware=malware_file is not None)  # 악성 데이터 로드 여부 결정

    if pe_all.empty:
        print("데이터가 비어 있습니다. 파일 경로를 확인하세요.")
        exit()

    gram_all = data_loader.load_ngram()

    preprocessor = DataPreprocessor(pe_all)
    pe_all = preprocessor.filter_na()
    pe_all = preprocessor.drop_columns(['filename', 'MD5', 'packer_type'])
    X, Y = preprocessor.get_features_and_labels()

    X = preprocessor.remove_constant_features(X)  # 상수 특성 제거

    feature_selector = FeatureSelector(X, Y)
    X = feature_selector.select_features()
    # X = feature_selector.apply_pca()  # PCA 사용 시 주석 해제

    classifier = Classifiers(X, Y)
    results = {
        'svm': classifier.do_svm(),
        'randomforest': classifier.do_randomforest(),
        'naivebayes': classifier.do_naivebayes(),
        'dnn': classifier.do_dnn(epochs=10)  # 에포크 수 설정
    }

    # 평가 결과를 콘솔에 출력
    print("모델 평가 결과:")
    for model, accuracy in results.items():
        print(f"{model}: {accuracy:.4f}")
