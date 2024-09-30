import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
import tensorflow as tf
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.utils import to_categorical

class Classifiers:
    def __init__(self, X, Y):
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(X, Y, test_size=0.2, random_state=0)
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
        self.y_train = to_categorical(self.y_train)
        self.y_test = to_categorical(self.y_test)

        input_len = np.size(self.x_train, 1)
        num_classes = self.y_train.shape[1]

        model = Sequential()
        model.add(Dense(1024, input_dim=input_len, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(512, activation='sigmoid'))
        model.add(Dropout(0.5))
        model.add(Dense(256, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(num_classes, activation='softmax'))

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
