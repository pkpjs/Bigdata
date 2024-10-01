import pandas as pd
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.decomposition import PCA
from sklearn.feature_selection import VarianceThreshold

class DataPreprocessor:
    def __init__(self, data):
        self.data = data

    def filter_na(self):
        self.data = self.data.dropna()
        return self.data

    def drop_columns(self, columns):
        self.data = self.data.drop(columns, axis=1)
        return self.data

    def get_features_and_labels(self):
        Y = self.data['class']
        X = self.data.drop('class', axis=1)
        return X, Y

    def remove_constant_features(self, X):
        selector = VarianceThreshold(threshold=0)
        return selector.fit_transform(X)

class FeatureSelector:
    def __init__(self, X, Y, k_features=50):
        self.X = X
        self.Y = Y
        self.k_features = k_features

    def select_features(self):
        X_selected = SelectKBest(f_classif, k=self.k_features).fit_transform(self.X, self.Y)
        return X_selected

    def apply_pca(self, n_components=50):
        pca = PCA(n_components=n_components)
        X_pca = pca.fit_transform(self.X)
        return X_pca
