import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import OneHotEncoder, LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.decomposition import PCA
import tensorflow as tf
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.utils import to_categorical
from sklearn.ensemble import RandomForestClassifier

class Classifiers():
    def __init__(self, X, Y):
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(X, Y, test_size=0.2, random_state=0)

        # 데이터 정규화
        self.scaler = StandardScaler().fit(self.x_train)
        self.x_train = self.scaler.transform(self.x_train)
        self.x_test = self.scaler.transform(self.x_test)

    def do_svm(self):
        parameters = {'C': [0.1, 1, 10], 'gamma': [0.01, 0.1, 1]}
        clf = GridSearchCV(SVC(), parameters, cv=5)
        clf.fit(self.x_train, self.y_train)
        best_clf = clf.best_estimator_
        y_pred = best_clf.predict(self.x_test)
        return accuracy_score(self.y_test, y_pred)

    def do_randomforest(self, mode):
        parameters = {'n_estimators': [100, 200], 'max_depth': [None, 10, 20]}
        clf = GridSearchCV(RandomForestClassifier(), parameters, cv=5)
        clf.fit(self.x_train, self.y_train)
        best_clf = clf.best_estimator_
        if mode == 1:
            return best_clf.feature_importances_
        y_pred = best_clf.predict(self.x_test)
        return accuracy_score(self.y_test, y_pred)

    def do_naivebayes(self):
        clf = GaussianNB()
        clf.fit(self.x_train, self.y_train)
        y_pred = clf.predict(self.x_test)
        return accuracy_score(self.y_test, y_pred)

    def do_dnn(self):
        seed = 0
        np.random.seed(seed)
        tf.compat.v1.set_random_seed(seed)

        self.x_train = np.asarray(self.x_train).astype('float32')
        self.x_test = np.asarray(self.x_test).astype('float32')
        self.y_train = to_categorical(self.y_train)  # One-hot encode the labels for multi-class classification
        self.y_test = to_categorical(self.y_test)    # One-hot encode the labels for multi-class classification

        input_len = np.size(self.x_train, 1)
        num_classes = self.y_train.shape[1]

        model = Sequential()
        model.add(Dense(1024, input_dim=input_len, activation='relu'))
        model.add(Dropout(0.5))  # Dropout to prevent overfitting
        model.add(Dense(512, activation='sigmoid'))  # Sigmoid activation function
        model.add(Dropout(0.5))  # Dropout to prevent overfitting
        model.add(Dense(256, activation='relu'))  # ReLU activation function
        model.add(Dropout(0.5))  # Dropout to prevent overfitting
        model.add(Dense(num_classes, activation='softmax'))  # Use softmax for multi-class classification

        model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
        model.fit(self.x_train, self.y_train, epochs=10, batch_size=128)

        accuracy = model.evaluate(self.x_test, self.y_test)[1]
        print("\n Accuracy: %.4f" % accuracy)

        y_pred = np.argmax(model.predict(self.x_test), axis=1)
        y_true = np.argmax(self.y_test, axis=1)
        acc = accuracy_score(y_true, y_pred)
        return acc

    def do_all(self):
        rns = []
        rns.append(self.do_svm())
        rns.append(self.do_randomforest(0))
        rns.append(self.do_naivebayes())
        rns.append(self.do_dnn())
        return rns

    # 데이터 로드 및 전처리
pe_nor = pd.read_csv('normal_pe (1).csv')
pe_mal = pd.read_csv('malware_pe (1).csv')
pe_all = pd.concat([pe_nor, pe_mal])  # 998 x 72

# ngram 특징 데이터 로드
gram_all = pd.read_csv('ngram (1).csv')

print(pe_all.shape, gram_all.shape)
print("[*] Before Filtering NA values: ", pe_all.shape)
NA_values = pe_all.isnull().values.sum()
print("[*] Missing Values: ", NA_values)
pe_all = pe_all.dropna()
print("[*] After Filtering NA values: ", pe_all.shape)
pe_all.head()

pe_all_tmp = pe_all  # 데이터 백업

pe_all = pe_all.drop(['filename', 'MD5', 'packer_type'], axis=1)  # 파일이름, MD5, packer_type 열 제거
print(pe_all.shape)
print(pe_all.head())

Y = pe_all['class']  # 카테고리 열을 별도로 추출
X = pe_all.drop('class', axis=1)  # 카테고리 열 제거
Y_bak = Y  # 뒤에서 진행할 특징 선택 작업을 위해 데이터 백업
print(X.head())

# 특성 선택 (선택적으로 PCA 사용)
X = SelectKBest(f_classif, k=50).fit_transform(X, Y)
pca = PCA(n_components=50)
X = pca.fit_transform(X)

md_pe = Classifiers(X, Y)  # 학습 모듈 인스턴스 초기화
df = pd.DataFrame(columns=["svm", "randomforest", "naivebayes", "dnn"])
df.loc['pe'] = md_pe.do_all()  # 분류 모델 학습
print(df)
print(X.shape, Y.shape)  # X: 937 x 68 / Y: 937 x 1

def hot_encoding(df):
    enc = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    lab = LabelEncoder()
    dat = df['packer_type']
    lab.fit(dat)
    lab_dat = lab.transform(dat)
    df = df.drop('packer_type', axis=1)
    lab_dat = lab_dat.reshape(len(lab_dat), 1)
    enc_dat = enc.fit_transform(lab_dat)
    enc_dat = pd.DataFrame(enc_dat, columns=lab.classes_)
    df = df.reset_index(drop=True)
    enc_dat = enc_dat.reset_index(drop=True)
    df = pd.concat([df, enc_dat], axis=1)
    return df, lab.classes_

pe_all = pe_all_tmp
pe_all = pe_all.drop(['filename', 'MD5'], axis=1)  # 파일이름, MD5 열 제거
pe_all, classes_ = hot_encoding(pe_all)  # One-Hot 인코딩 변환
print("Found %d Categories in packer-type" % len(classes_))

# dataset for modeling
pe_all = pd.DataFrame(pe_all)
pe_all.to_csv('pe_packer.csv', index=False)

Y = pe_all['class']  # 카테고리 열을 별도로 추출
X = pe_all.drop('class', axis=1)

# 특성 선택 (선택적으로 PCA 사용)
# X = SelectKBest(f_classif, k=50).fit_transform(X, Y)
# pca = PCA(n_components=50)
# X = pca.fit_transform(X)

md_pe_packer = Classifiers(X, Y)  # 학습 모듈 인스턴스 초기화
df.loc['pe_packer'] = md_pe_packer.do_all()  # 분류 모델 학습
print(X.shape, Y.shape)  # X: 937 x 87 / Y: 937 x 1

gram_all = gram_all.drop(['filename', 'MD5'], axis=1)  # 파일이름, MD5 열 제거
print("ngram", gram_all.shape)

Y = gram_all['class']  # 카테고리 열을 별도로 추출
X = gram_all.drop('class', axis=1)  # 카테고리 열 제거

# 특성 선택 (선택적으로 PCA 사용)
# X = SelectKBest(f_classif, k=50).fit_transform(X, Y)
# pca = PCA(n_components=50)
# X = pca.fit_transform(X)

md_gram = Classifiers(X, Y)  # 학습 모듈 인스턴스 초기화
df.loc['ngram'] = md_gram.do_all()
df.loc['image'] = [0, 0, 0, 0]

print(X.shape, Y.shape)  # X: 937 x 100 / Y: 937 x 1

# cn = cnn_model1.CNN_tensor()
# cn.load_images()
# cnn_acc = cn.do_cnn()
print(df)
avg_pe = df.loc['pe'].mean(axis=0)
avg_pe_packer = df.loc['pe_packer'].mean(axis=0)
avg_gram = df.loc['ngram'].mean(axis=0)
df.loc['avg'] = [avg_pe, avg_pe_packer, avg_gram, 0]
print(df)