import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from keras.models import Sequential
from keras.layers import Dense, Dropout, Input
from keras.utils import to_categorical
from model_evaluator import ModelEvaluator

class Classifiers:
    def __init__(self, X, Y):
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(X, Y, test_size=0.2, random_state=0)
        self.scaler = StandardScaler().fit(self.x_train)
        self.x_train = self.scaler.transform(self.x_train)
        self.x_test = self.scaler.transform(self.x_test)

    def do_svm(self):
        model = SVC()
        evaluator = ModelEvaluator(model, self.x_train, self.y_train, self.x_test, self.y_test)
        evaluator.train()
        accuracy, predictions = evaluator.evaluate()  # 정확도와 예측 결과 반환
        return accuracy, predictions

    def do_randomforest(self):
        model = RandomForestClassifier()
        evaluator = ModelEvaluator(model, self.x_train, self.y_train, self.x_test, self.y_test)
        evaluator.train()
        accuracy, predictions = evaluator.evaluate()  # 정확도와 예측 결과 반환
        return accuracy, predictions

    def do_naivebayes(self):
        model = GaussianNB()
        evaluator = ModelEvaluator(model, self.x_train, self.y_train, self.x_test, self.y_test)
        evaluator.train()
        accuracy, predictions = evaluator.evaluate()  # 정확도와 예측 결과 반환
        return accuracy, predictions

    def do_dnn(self, epochs=10):  # epochs 매개변수 추가
        model = Sequential()
        model.add(Input(shape=(self.x_train.shape[1],)))  # Input layer 추가
        model.add(Dense(1024, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(512, activation='sigmoid'))
        model.add(Dropout(0.5))
        model.add(Dense(256, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(len(np.unique(self.y_train)), activation='softmax'))

        model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
        model.fit(self.x_train, to_categorical(self.y_train), epochs=epochs, batch_size=128, verbose=1)

        accuracy = model.evaluate(self.x_test, to_categorical(self.y_test), verbose=0)[1]
        predictions = np.argmax(model.predict(self.x_test), axis=1)  # 예측 결과 저장
        return accuracy, predictions  # 정확도와 예측 결과 반환
