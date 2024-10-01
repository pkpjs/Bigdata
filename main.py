from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers

if __name__ == "__main__":
    data_loader = DataLoader('normal_pe (1).csv', 'malware_pe (1).csv', 'ngram (1).csv')
    pe_all = data_loader.load_data()
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
        'dnn': classifier.do_dnn()
    }

    print("Model Evaluation Results:")
    print(results)
