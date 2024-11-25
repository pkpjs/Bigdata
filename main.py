# -*- coding: utf-8 -*-
from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QGraphicsView
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib.pyplot as plt
from matplotlib import font_manager, rc
import pandas as pd
import numpy as np
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
import os

# TensorFlow 경고 메시지 제거 (선택 사항)
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# 한글 폰트 설정
font_path = "C:/Windows/Fonts/malgun.ttf"  # Windows: 맑은 고딕
font = font_manager.FontProperties(fname=font_path).get_name()
rc('font', family=font)
plt.rcParams['axes.unicode_minus'] = False  # 음수 기호가 깨지지 않도록 설정

class GraphThread(QThread):
    graph_drawn = pyqtSignal()

    def __init__(self, view, x, y, title='Graph', xlabel='X-axis', ylabel='Y-axis', linestyle='-', marker='o', color='blue'):
        super().__init__()
        self.view = view
        self.x = x
        self.y = y
        self.title = title
        self.xlabel = xlabel
        self.ylabel = ylabel
        self.linestyle = linestyle
        self.marker = marker
        self.color = color

    def run(self):
        # matplotlib로 그래프 그리기
        fig, ax = plt.subplots()
        ax.plot(self.x, self.y, linestyle=self.linestyle, marker=self.marker, color=self.color)

        ax.set_title(self.title)
        ax.set_xlabel(self.xlabel)
        ax.set_ylabel(self.ylabel)
        ax.grid(True)

        # Figure를 QImage로 변환하여 QGraphicsView에 표시
        canvas = FigureCanvas(fig)
        canvas.draw()

        # canvas 이미지를 RGBA 바이트 배열로 변환
        width, height = canvas.get_width_height()
        image = QImage(canvas.buffer_rgba(), width, height, QImage.Format_RGBA8888)

        # QPixmap으로 변환 후 QGraphicsScene에 추가
        pixmap = QPixmap.fromImage(image)
        scene = QGraphicsScene()
        scene.addPixmap(pixmap)
        self.view.setScene(scene)

        # 메모리 해제
        plt.close(fig)

        # 그래프 그리기 완료 신호 발생
        self.graph_drawn.emit()

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)

        # UI 위젯 초기화
        self.status_data_preprocessing = self.findChild(QtWidgets.QLabel, 'status_data_preprocessing')
        self.status_model_training = self.findChild(QtWidgets.QLabel, 'status_model_training')
        self.train_button = self.findChild(QtWidgets.QPushButton, 'train_button')
        self.data_select = self.findChild(QtWidgets.QPushButton, 'data_select')
        self.malware_file = self.findChild(QtWidgets.QLineEdit, 'malware_file')
        self.preprocessing_result = self.findChild(QtWidgets.QTableWidget, 'preprocessing_result')
        self.train_result = self.findChild(QtWidgets.QTableWidget, 'train_result')
        self.graphicsView = self.findChild(QGraphicsView, 'graphicsView')

        # 초기 상태 설정
        if self.status_data_preprocessing:
            self.status_data_preprocessing.setText("대기 중")
        if self.status_model_training:
            self.status_model_training.setText("대기 중")

        # 훈련 버튼 클릭 연결
        if self.train_button:
            self.train_button.clicked.connect(self.handle_train)

        # 데이터 선택 버튼 클릭 연결
        if self.data_select:
            self.data_select.clicked.connect(self.select_malware_file)

    def select_malware_file(self):
        # 파일 선택 다이얼로그
        malware_file, _ = QFileDialog.getOpenFileName(self, "악성 데이터 파일을 선택하세요", "", "CSV Files (*.csv)")
        if malware_file:
            self.malware_file.setText(malware_file)

    def handle_train(self):
        print("훈련 시작")
        if self.status_data_preprocessing:
            self.status_data_preprocessing.setText("전처리 중...")

        malware_file = self.malware_file.text().strip()
        if not malware_file:
            QMessageBox.critical(self, "오류", "악성코드 파일을 선택하세요.")
            return

        try:
            # 데이터 로드
            data_loader = DataLoader(malware_file=malware_file)
            pe_all = data_loader.load_data()
            print(f"데이터 로딩 완료: {pe_all.shape}")

            # 데이터 전처리
            preprocessor = DataPreprocessor(pe_all)
            preprocessor.filter_na()
            print(f"NA 제거 후 데이터 크기: {pe_all.shape}")

            # 필요 없는 열 제거
            drop_columns = [col for col in ['filename', 'packer_type'] if col in pe_all.columns]
            preprocessor.drop_columns(drop_columns)

            # 숫자형 데이터만 선택
            X, Y = preprocessor.get_features_and_labels()
            print(f"전처리 후 특징 크기: {X.shape}, 레이블 크기: {Y.shape}")

            # 데이터 스케일링
            from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            X = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
            print("데이터 스케일링 완료")

            # 상수 제거
            X = preprocessor.remove_constant_features(X)
            print(f"상수 제거 후 특징 크기: {X.shape}")

            # 특징 선택
            k_features = min(20, X.shape[1])  # 20개 특징 선택
            feature_selector = FeatureSelector(X, Y, k_features=k_features)
            X_new = pd.DataFrame(feature_selector.select_features(),
                                 columns=[f'Feature {i}' for i in range(1, k_features + 1)])
            print(f"선택된 특징 크기: {X_new.shape}")

            # 전처리 결과가 비어 있는지 확인
            if X_new.empty:
                print("전처리 결과가 비어 있습니다. 데이터를 확인하세요.")
                QMessageBox.critical(self, "오류", "전처리 결과가 비어 있습니다. 데이터를 확인하세요.")
                return

            # 전처리 결과 표시
            if self.preprocessing_result:
                self.preprocessing_result.setVisible(True)
                self.preprocessing_result.setRowCount(len(X_new))
                self.preprocessing_result.setColumnCount(len(X_new.columns))
                self.preprocessing_result.setHorizontalHeaderLabels(X_new.columns.tolist())

                # 데이터 삽입
                for row_idx, row in X_new.iterrows():
                    for col_idx, value in enumerate(row):
                        item = QtWidgets.QTableWidgetItem(str(value))
                        self.preprocessing_result.setItem(row_idx, col_idx, item)

            # 전처리 상태 업데이트
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("전처리 완료")

            # 모델 학습을 별도의 쓰레드로 처리
            self.train_thread = TrainThread(X_new, Y)
            self.train_thread.training_complete.connect(self.on_training_complete)
            self.train_thread.start()

        except Exception as e:
            print(f"훈련 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"훈련 중 오류가 발생했습니다: {e}")
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("대기 중")
            if self.status_model_training:
                self.status_model_training.setText("대기 중")

    def on_training_complete(self, results):
        # 학습 완료 후 UI 업데이트
        if not self.train_result:
            print("train_result 테이블을 찾을 수 없습니다.")
            return

        self.train_result.setColumnCount(4)
        self.train_result.setHorizontalHeaderLabels(['Model', 'Accuracy', 'Malicious Count', 'Benign Count'])
        self.train_result.setRowCount(len(results))

        for row, (model, (accuracy, predictions)) in enumerate(results.items()):
            self.train_result.setItem(row, 0, QtWidgets.QTableWidgetItem(model))
            self.train_result.setItem(row, 1, QtWidgets.QTableWidgetItem(f"{accuracy:.4f}"))
            self.train_result.setItem(row, 2, QtWidgets.QTableWidgetItem(str((predictions == 1).sum())))
            self.train_result.setItem(row, 3, QtWidgets.QTableWidgetItem(str((predictions == 0).sum())))

        # 그래프 그리기 쓰레드 실행
        model_names = list(results.keys())
        accuracies = [result[0] for result in results.values()]
        self.graph_thread = GraphThread(
            view=self.graphicsView,
            x=model_names,
            y=accuracies,
            title='모델 정확도 비교',
            xlabel='모델',
            ylabel='정확도',
            linestyle='-',
            marker='o'
        )
        self.graph_thread.graph_drawn.connect(self.on_graph_drawn)
        self.graph_thread.start()

    def on_graph_drawn(self):
        if self.status_model_training:
            self.status_model_training.setText("모델 학습 및 그래프 완료")

class TrainThread(QThread):
    training_complete = pyqtSignal(dict)

    def __init__(self, X, Y):
        super().__init__()
        self.X = X
        self.Y = Y

    def run(self):
        try:
            classifier = Classifiers(self.X, self.Y)
            results = {
                'svm': classifier.do_svm(),
                'randomforest': classifier.do_randomforest(n_estimators=200, max_depth=20),
                'naivebayes': classifier.do_naivebayes(),
                'dnn': classifier.do_dnn(epochs=100)  # DNN 추가
            }
            print("모델 학습 완료")
            self.training_complete.emit(results)
        except Exception as e:
            print(f"모델 학습 중 오류 발생: {e}")


def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()


if __name__ == "__main__":
    create_file_selector()
