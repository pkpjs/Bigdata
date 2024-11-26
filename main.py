from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QGraphicsView
from PyQt5.QtCore import QThread, pyqtSignal, Qt
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

# 한글 폰트 설정 (Windows: 맑은 고딕)
font_path = "C:/Windows/Fonts/malgun.ttf"
font = font_manager.FontProperties(fname=font_path).get_name()
rc('font', family=font)
plt.rcParams['axes.unicode_minus'] = False  # 음수 기호가 깨지지 않도록 설정

class GraphThread(QThread):
    graph_drawn = pyqtSignal(QImage)  # QImage를 전달하는 시그널

    def __init__(self, x, y, title='Graph', xlabel='X-axis', ylabel='Y-axis', linestyle='-', marker='o', color='blue'):
        super().__init__()
        self.x = x
        self.y = y
        self.title = title
        self.xlabel = xlabel
        self.ylabel = ylabel
        self.linestyle = linestyle
        self.marker = marker
        self.color = color

    def run(self):
        try:
            # matplotlib로 그래프 그리기
            fig, ax = plt.subplots()
            ax.bar(self.x, self.y, color=self.color)
            ax.set_title(self.title)
            ax.set_xlabel(self.xlabel)
            ax.set_ylabel(self.ylabel)
            ax.set_xticklabels(self.x, rotation=45, ha='right')
            ax.grid(True, axis='y')

            # Figure를 QImage로 변환
            canvas = FigureCanvas(fig)
            canvas.draw()

            width, height = fig.canvas.get_width_height()
            buf = canvas.buffer_rgba()
            image = QImage(buf, width, height, QImage.Format_RGBA8888)

            # 메모리 해제
            plt.close(fig)

            # 그래프 이미지를 시그널로 전달
            self.graph_drawn.emit(image)
        except Exception as e:
            print(f"그래프 생성 중 오류 발생: {e}")
            self.graph_drawn.emit(None)

class TrainThread(QThread):
    training_complete = pyqtSignal(dict)

    def __init__(self, X, Y):
        super().__init__()
        self.X = X
        self.Y = Y

    def run(self):
        try:
            classifier = Classifiers(self.X, self.Y)
            results = {}
            for model_name, model_func in [
                ('SVM', classifier.do_svm),
                ('Random Forest', lambda: classifier.do_randomforest(n_estimators=200, max_depth=20)),
                ('Naive Bayes', classifier.do_naivebayes),
                ('DNN', lambda: classifier.do_dnn(epochs=10))
            ]:
                accuracy, _ = model_func()
                results[model_name] = accuracy
            print("모델 학습 완료")
            self.training_complete.emit(results)
        except Exception as e:
            print(f"모델 학습 중 오류 발생: {e}")
            self.training_complete.emit({})

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

        # 버튼 클릭 연결
        if self.train_button:
            self.train_button.clicked.connect(self.handle_train)

        if self.data_select:
            self.data_select.clicked.connect(self.select_malware_file)

    def select_malware_file(self):
        # 파일 선택 다이얼로그
        malware_file, _ = QFileDialog.getOpenFileName(self, "데이터 파일을 선택하세요", "", "CSV Files (*.csv)")
        if malware_file:
            self.malware_file.setText(malware_file)

    def handle_train(self):
        print("훈련 시작")
        if self.status_data_preprocessing:
            self.status_data_preprocessing.setText("전처리 중...")

        malware_file = self.malware_file.text().strip()
        if not malware_file:
            QMessageBox.critical(self, "오류", "데이터 파일을 선택하세요.")
            return

        try:
            # 데이터 로드
            data_loader = DataLoader(malware_file=malware_file)
            pe_all = data_loader.load_data()
            print(f"데이터 로딩 완료: {pe_all.shape}")

            # 데이터 전처리
            preprocessor = DataPreprocessor(pe_all)
            preprocessor.filter_na()
            print(f"NA 제거 후 데이터 크기: {preprocessor.data.shape}")

            # 'SHA256'을 보존한 후 필요 없는 열 제거
            if 'SHA256' in preprocessor.data.columns:
                sha256_values = preprocessor.data['SHA256'].values
            else:
                sha256_values = np.array(['Unknown'] * preprocessor.data.shape[0])
                print("경고: 'SHA256' 열이 존재하지 않습니다. 모든 샘플의 SHA256을 'Unknown'으로 설정합니다.")

            # 필요 없는 열 제거 (여기서는 'SHA256'만 제거)
            drop_columns = [col for col in ['SHA256'] if col in preprocessor.data.columns]
            preprocessor.drop_columns(drop_columns)
            print(f"필요 없는 열 제거 후 데이터 크기: {preprocessor.data.shape}")

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

            # 데이터 저장: Type별로 분리하여 CSV 파일로 저장
            self.save_data_by_type(preprocessor.data, malware_file)

            # 모델 학습을 별도의 쓰레드로 처리
            self.train_thread = TrainThread(X_new, Y)
            self.train_thread.training_complete.connect(self.on_training_complete)
            self.train_thread.start()

            # 모델 학습 상태 업데이트
            if self.status_model_training:
                self.status_model_training.setText("모델 학습 중...")

        except Exception as e:
            print(f"훈련 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"훈련 중 오류가 발생했습니다: {e}")
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("대기 중")
            if self.status_model_training:
                self.status_model_training.setText("대기 중")

    def save_data_by_type(self, data, input_csv):
        try:
            # 출력 디렉터리 설정
            output_dir = os.path.join(os.path.dirname(input_csv), 'split_by_type')
            os.makedirs(output_dir, exist_ok=True)

            # Type별 데이터 분리 및 저장
            type_groups = data.groupby('Type')
            for type_value, group in type_groups:
                file_name = f"type_{type_value}.csv"
                file_path = os.path.join(output_dir, file_name)
                group.to_csv(file_path, index=False, encoding='utf-8-sig')

            print(f"Type별로 데이터가 {output_dir}에 저장되었습니다.")
            QMessageBox.information(self, "완료", f"Type별로 데이터가 저장되었습니다:\n{output_dir}")

        except Exception as e:
            print(f"데이터 저장 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"데이터 저장 중 오류가 발생했습니다: {e}")

    def on_training_complete(self, results):
        try:
            if not results:
                print("훈련 결과가 비어 있습니다.")
                QMessageBox.critical(self, "오류", "훈련 결과가 비어 있습니다.")
                return

            # 학습 완료 후 UI 업데이트
            if not self.train_result:
                print("train_result 테이블을 찾을 수 없습니다.")
                return

            self.train_result.setColumnCount(2)
            self.train_result.setHorizontalHeaderLabels(['Model', 'Accuracy'])
            self.train_result.setRowCount(len(results))

            for row, (model, accuracy) in enumerate(results.items()):
                self.train_result.setItem(row, 0, QtWidgets.QTableWidgetItem(model))
                self.train_result.setItem(row, 1, QtWidgets.QTableWidgetItem(f"{accuracy:.4f}"))

            # 그래프 그리기 쓰레드 실행
            model_names = list(results.keys())
            accuracies = list(results.values())
            self.graph_thread = GraphThread(
                x=model_names,
                y=accuracies,
                title='모델 정확도 비교',
                xlabel='모델',
                ylabel='정확도',
                linestyle='-',
                marker='o',
                color='skyblue'
            )
            self.graph_thread.graph_drawn.connect(self.on_graph_drawn)
            self.graph_thread.start()
        except Exception as e:
            print(f"학습 결과 처리 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"학습 결과 처리 중 오류가 발생했습니다: {e}")

    def on_graph_drawn(self, image):
        try:
            if image is None:
                QMessageBox.critical(self, "오류", "그래프 생성 중 오류가 발생했습니다.")
                if self.status_model_training:
                    self.status_model_training.setText("모델 학습 완료 (그래프 생성 실패)")
                return

            # QImage를 QPixmap으로 변환 후 QGraphicsScene에 추가
            pixmap = QPixmap.fromImage(image)
            scene = QGraphicsScene()
            scene.addPixmap(pixmap)
            self.graphicsView.setScene(scene)

            # 그래프 그리기 완료 상태 업데이트
            if self.status_model_training:
                self.status_model_training.setText("모델 학습 및 그래프 완료")
        except Exception as e:
            print(f"그래프 표시 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"그래프 표시 중 오류가 발생했습니다: {e}")

def create_app():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()

if __name__ == "__main__":
    create_app()
