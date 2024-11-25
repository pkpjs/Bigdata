import pandas as pd
from sklearn.feature_selection import VarianceThreshold

class DataPreprocessor:
    def __init__(self, data):
        self.data = data

    def filter_na(self):
        # NaN 값을 제거한 후 데이터 크기 출력
        self.data = self.data.dropna()
        return self.data

    def drop_columns(self, columns):
        # 지정된 열을 제거한 후 데이터 크기 출력
        self.data = self.data.drop(columns, axis=1)
        return self.data

    def get_features_and_labels(self):
        # 숫자 열만 선택
        numeric_data = self.data.select_dtypes(include=['number'])
        Y = numeric_data['Type']
        X = numeric_data.drop('Type', axis=1)
        return X, Y

    def remove_constant_features(self, X):
        # 상수 열 제거
        selector = VarianceThreshold(threshold=0)
        X = selector.fit_transform(X)
        return X


class FeatureSelector:
    def __init__(self, X, Y, k_features=50):
        self.X = X
        self.Y = Y
        self.k_features = k_features

    def select_features(self):
        from sklearn.feature_selection import SelectKBest, f_classif
        # 모든 열과 행을 출력할 수 있도록 pandas 옵션 설정
        pd.set_option('display.max_columns', None)
        pd.set_option('display.max_rows', None)

        X_new = SelectKBest(f_classif, k=self.k_features).fit_transform(self.X, self.Y)
        print(f"\n최종 선택된 {self.k_features}개의 특성 데이터 요약:")
        print(pd.DataFrame(X_new).describe())  # 최종 선택된 특성 요약
        return X_new

    def apply_pca(self, n_components=50):
        from sklearn.decomposition import PCA
        X_pca = PCA(n_components=n_components).fit_transform(self.X)
        print(f"\nPCA 적용 후 {n_components}개의 주성분 데이터 요약:")
        print(pd.DataFrame(X_pca).describe())  # PCA 적용 후 데이터 요약
        return X_pca
