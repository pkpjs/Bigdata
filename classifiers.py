import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from keras.models import Sequential
from keras.layers import Dense, Dropout, Input
from keras.utils import to_categorical
from sklearn.metrics import accuracy_score


class Classifiers:
    def __init__(self, X, Y):
        # 데이터 분리
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(X, Y, test_size=0.2, random_state=0)

        # 데이터 스케일링
        self.scaler = StandardScaler().fit(self.x_train)
        self.x_train = self.scaler.transform(self.x_train)
        self.x_test = self.scaler.transform(self.x_test)

    def do_svm(self):
        # SVM 모델 생성 및 학습
        model = SVC()
        model.fit(self.x_train, self.y_train)
        predictions = model.predict(self.x_test)
        accuracy = accuracy_score(self.y_test, predictions)
        return accuracy, predictions

    def do_randomforest(self, n_estimators=100, max_depth=None):
        # Random Forest 모델 생성 및 학습
        model = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth, random_state=0)
        model.fit(self.x_train, self.y_train)
        predictions = model.predict(self.x_test)
        accuracy = accuracy_score(self.y_test, predictions)
        return accuracy, predictions

    def do_naivebayes(self):
        # Naive Bayes 모델 생성 및 학습
        model = GaussianNB()
        model.fit(self.x_train, self.y_train)
        predictions = model.predict(self.x_test)
        accuracy = accuracy_score(self.y_test, predictions)
        return accuracy, predictions

    def do_dnn(self, epochs=10, batch_size=128):
        # DNN 모델 생성 및 학습
        model = Sequential()
        model.add(Input(shape=(self.x_train.shape[1],)))
        model.add(Dense(1024, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(512, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(256, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(len(np.unique(self.y_train)), activation='softmax'))

        # 모델 컴파일 및 학습
        model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
        model.fit(self.x_train, to_categorical(self.y_train), epochs=epochs, batch_size=batch_size, verbose=1)

        # 평가 및 예측
        accuracy = model.evaluate(self.x_test, to_categorical(self.y_test), verbose=0)[1]
        predictions = np.argmax(model.predict(self.x_test), axis=1)
        return accuracy, predictions
