from sklearn.metrics import accuracy_score

class ModelEvaluator:
    def __init__(self, model, x_train, y_train, x_test, y_test):
        self.model = model
        self.x_train = x_train
        self.y_train = y_train
        self.x_test = x_test
        self.y_test = y_test

    def train(self):
        self.model.fit(self.x_train, self.y_train)

    def evaluate(self):
        y_pred = self.model.predict(self.x_test)
        accuracy = accuracy_score(self.y_test, y_pred)
        return accuracy, y_pred  # 정확도와 예측 결과 반환
