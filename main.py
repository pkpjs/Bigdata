from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QMessageBox,
    QGraphicsView, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QUrl
from PyQt5.QtGui import QImage, QPixmap, QDesktopServices
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib.pyplot as plt
from matplotlib import font_manager, rc
import pandas as pd
import numpy as np
import os
import json  # For debugging

from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from virustotal_thread import VirusTotalThread  # VirusTotalThread 클래스 임포트
from sklearn.preprocessing import StandardScaler  # StandardScaler 임포트

# 한글 폰트 설정 (Windows: 맑은 고딕)
font_path = "C:/Windows/Fonts/malgun.ttf"
font = font_manager.FontProperties(fname=font_path).get_name()
rc('font', family=font)
plt.rcParams['axes.unicode_minus'] = False  # 음수 기호가 까지지 않도록 설정


class GraphThread(QThread):
    graph_drawn = pyqtSignal(QImage)  # QImage를 전달하는 시그널

    def __init__(self, x, y, title='Graph', xlabel='X-axis', ylabel='Y-axis', color='blue'):
        super().__init__()
        self.x = x
        self.y = y
        self.title = title
        self.xlabel = xlabel
        self.ylabel = ylabel
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
                ('DNN', lambda: classifier.do_dnn(epochs=100))
            ]:
                accuracy, predictions = model_func()
                benign_count = np.sum(predictions == 0)
                malicious_count = np.sum(predictions == 1)
                results[model_name] = {'accuracy': accuracy, 'benign': benign_count, 'malicious': malicious_count}
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
        self.vir_result = self.findChild(QtWidgets.QTableWidget, 'vir_result')
        self.api_key_input = self.findChild(QtWidgets.QLineEdit, 'api_key_input')

        # QGraphicsView 설정
        self.scene = QGraphicsScene()
        self.graphicsView.setScene(self.scene)

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

        # VirusTotal 결과 테이블 설정
        self.setup_vir_result_table()

    def setup_vir_result_table(self):
        """
        vir_result 테이블을 설정하고, VirusTotal URL 열을 더블 클릭하면 이 URL으로 웹 브라우저를 연결하도록 연결합니다.
        """
        if self.vir_result:
            self.vir_result.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            self.vir_result.cellDoubleClicked.connect(self.open_url)

    def open_url(self, row, column):
        URL_COLUMN_INDEX = 3  # VirusTotal URL이 있는 열의 인덱스

        if column == URL_COLUMN_INDEX:
            item = self.vir_result.item(row, column)
            if item:
                url = item.text()
                if url and url != "URL 없음":
                    QDesktopServices.openUrl(QUrl(url))
                else:
                    QMessageBox.information(self, "정보", "유효한 URL이 없습니다.")

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

            # 'SHA256'을 보존
            if 'SHA256' in preprocessor.data.columns:
                sha256_values = preprocessor.data['SHA256'].values
            else:
                sha256_values = np.array(['Unknown'] * preprocessor.data.shape[0])
                print("경고: 'SHA256' 열이 존재하지 않습니다. 모든 샘플의 SHA256을 'Unknown'으로 설정합니다.")

            # 모델 학습을 위한 숫자형 데이터만 선택
            X, Y = preprocessor.get_features_and_labels()
            print(f"전처리 후 특징 크기: {X.shape}, 레이블 크기: {Y.shape}")

            # 'SHA256'을 모델 특징에서 제외
            if 'SHA256' in X.columns:
                X = X.drop('SHA256', axis=1)
                print("모델 학습을 위해 'SHA256' 열을 제외했습니다.")

            # 데이터 스케일링
            scaler = StandardScaler()
            X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
            print("데이터 스케일링 완료")

            # 상수 제거
            X_scaled = preprocessor.remove_constant_features(X_scaled)
            print(f"상수 제거 후 특징 크기: {X_scaled.shape}")

            # 특징 선택
            k_features = min(20, X_scaled.shape[1])
            feature_selector = FeatureSelector(X_scaled, Y, k_features=k_features)
            selected_features = feature_selector.select_features()
            X_new = pd.DataFrame(selected_features, columns=[f'Feature {i}' for i in range(1, k_features + 1)])
            print(f"선택된 특징 크기: {X_new.shape}")

            if X_new.empty:
                print("전처리 결과가 비어 있습니다. 데이터를 확인하세요.")
                QMessageBox.critical(self, "오류", "전처리 결과가 비어 있습니다. 데이터를 확인하세요.")
                if self.status_data_preprocessing:
                    self.status_data_preprocessing.setText("대기 중")
                return

            # 전처리 결과 표시
            if self.preprocessing_result:
                self.preprocessing_result.setVisible(True)
                self.preprocessing_result.setRowCount(len(X_new))
                self.preprocessing_result.setColumnCount(len(X_new.columns))
                self.preprocessing_result.setHorizontalHeaderLabels(X_new.columns.tolist())

                for row_idx, row in X_new.iterrows():
                    for col_idx, value in enumerate(row):
                        item = QtWidgets.QTableWidgetItem(str(value))
                        self.preprocessing_result.setItem(row_idx, col_idx, item)

            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("전처리 완료")

            self.save_data_by_type(preprocessor.data, malware_file)

            self.X_new = X_new
            self.Y = Y

            grouped = preprocessor.data.groupby('Type')
            sampled_data = pd.concat([
                group.sample(n=2, random_state=42)
                for name, group in grouped if name in [1, 2, 3, 4, 5, 6] and len(group) >= 2
            ])
            sampled_data = sampled_data.sample(n=10, random_state=42)
            sha256_sampled = sampled_data['SHA256'].tolist()
            print(f"선택된 SHA256 해시 (Type별 2개씩, 총 10개): {sha256_sampled}")

            api_key = self.api_key_input.text().strip()
            if not api_key:
                QMessageBox.critical(self, "오류", "VirusTotal API 키를 입력하세요.")
                if self.status_data_preprocessing:
                    self.status_data_preprocessing.setText("대기 중")
                return

            # VirusTotal 검사 시작
            self.status_data_preprocessing.setText("VirusTotal 검사 중...")
            self.vt_thread = VirusTotalThread(sha256_sampled, api_key)
            self.vt_thread.vt_complete.connect(self.on_vt_complete)
            self.vt_thread.start()

        except Exception as e:
            print(f"데이터 처리 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"데이터 처리 중 오류가 발생했습니다: {e}")
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("대기 중")

    def on_vt_complete(self, vt_results):
        try:
            self.vt_results = vt_results
            print(f"VirusTotal 검사 완료: {vt_results}")

            # 샘플 데이터 출력 (디버깅용)
            if vt_results:
                sample_sha256 = next(iter(vt_results))
                print(f"샘플 SHA256: {sample_sha256}")
                print(f"샘플 데이터: {json.dumps(vt_results[sample_sha256], ensure_ascii=False, indent=4)}")

            # VirusTotal 결과 표시
            if self.vir_result:
                self.vir_result.setVisible(True)
                if "invalid_api_key" in vt_results:
                    QMessageBox.critical(self, "오류", "유효한 API 키가 아닙니다.")
                    if self.status_data_preprocessing:
                        self.status_data_preprocessing.setText("대기 중")
                    return

                valid_results = {k: v for k, v in vt_results.items() if k != "invalid_api_key"}
                self.vir_result.setRowCount(len(valid_results))
                self.vir_result.setColumnCount(4)
                self.vir_result.setHorizontalHeaderLabels(['SHA256', 'VirusTotal Data', 'Malware Name', 'VirusTotal URL'])

                for row, (sha256, data) in enumerate(valid_results.items()):
                    sha256_item = QtWidgets.QTableWidgetItem(sha256)
                    vt_data_item = QtWidgets.QTableWidgetItem(str(data.get('data', '조회 실패')) if data else "조회 실패")

                    # 'malware_name'과 'permalink' 대신 URL 형식 변경
                    malware_name = self.extract_malware_name(data)
                    # Construct the URL based on SHA256
                    permalink = f"https://www.virustotal.com/gui/file/{sha256}"

                    malware_name_item = QtWidgets.QTableWidgetItem(malware_name)
                    vt_url_item = QtWidgets.QTableWidgetItem(permalink)

                    self.vir_result.setItem(row, 0, sha256_item)
                    self.vir_result.setItem(row, 1, vt_data_item)
                    self.vir_result.setItem(row, 2, malware_name_item)
                    self.vir_result.setItem(row, 3, vt_url_item)

                self.save_virustotal_results(valid_results)

            # 모델 학습 시작
            try:
                if hasattr(self, 'X_new') and hasattr(self, 'Y') and self.X_new is not None and self.Y is not None:
                    self.train_thread = TrainThread(self.X_new, self.Y)
                    self.train_thread.training_complete.connect(self.on_training_complete)
                    self.train_thread.start()

                    if self.status_model_training:
                        self.status_model_training.setText("모델 학습 중...")
                    if self.status_data_preprocessing:
                        self.status_data_preprocessing.setText("전처리 완료 및 VirusTotal 검사 완료")
                else:
                    QMessageBox.critical(self, "오류", "모델 학습을 위한 데이터가 준비되지 않았습니다.")
            except Exception as e:
                print(f"모델 학습 준비 중 오류 발생: {e}")
                QMessageBox.critical(self, "오류", f"모델 학습 준비 중 오류가 발생했습니다: {e}")
                if self.status_data_preprocessing:
                    self.status_data_preprocessing.setText("전처리 완료")
                if self.status_model_training:
                    self.status_model_training.setText("대기 중")

        except Exception as e:
            print(f"VirusTotal 검사 후 처리 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"VirusTotal 검사 후 처리 중 오류가 발생했습니다: {e}")
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("전처리 완료")
            if self.status_model_training:
                self.status_model_training.setText("대기 중")

    def on_training_complete(self, results):
        try:
            if not results:
                QMessageBox.critical(self, "오류", "모델 학습에 실패했습니다.")
                if self.status_model_training:
                    self.status_model_training.setText("대기 중")
                return

            print(f"모델 학습 결과: {results}")

            # 업데이트 train_result 테이블
            if self.train_result:
                self.train_result.setVisible(True)
                self.train_result.setRowCount(len(results))
                self.train_result.setColumnCount(4)
                self.train_result.setHorizontalHeaderLabels(['모델', '정확도', '정상 샘플 수', '악성 샘플 수'])

                for row, (model_name, metrics) in enumerate(results.items()):
                    model_item = QtWidgets.QTableWidgetItem(model_name)
                    accuracy_item = QtWidgets.QTableWidgetItem(f"{metrics['accuracy']:.2f}")
                    benign_item = QtWidgets.QTableWidgetItem(str(metrics['benign']))
                    malicious_item = QtWidgets.QTableWidgetItem(str(metrics['malicious']))

                    self.train_result.setItem(row, 0, model_item)
                    self.train_result.setItem(row, 1, accuracy_item)
                    self.train_result.setItem(row, 2, benign_item)
                    self.train_result.setItem(row, 3, malicious_item)

            # 상태 업데이트
            if self.status_model_training:
                self.status_model_training.setText("모델 학습 완료")

            QMessageBox.information(self, "완료", "모델 학습이 성공적으로 완료되었습니다.")

            # 그래프 생성
            model_names = list(results.keys())
            accuracies = [results[model]['accuracy'] for model in model_names]

            # Create and start GraphThread
            self.graph_thread = GraphThread(
                x=model_names,
                y=accuracies,
                title='모델 정확도 비교',
                xlabel='모델',
                ylabel='정확도',
                color='skyblue'
            )
            self.graph_thread.graph_drawn.connect(self.on_graph_drawn)
            self.graph_thread.start()

        except Exception as e:
            print(f"모델 학습 후 처리 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"모델 학습 후 처리 중 오류가 발생했습니다: {e}")
            if self.status_model_training:
                self.status_model_training.setText("대기 중")

    def on_graph_drawn(self, image):
        """
        GraphThread에서 전달된 QImage를 QGraphicsView에 표시합니다.
        """
        if image is not None:
            pixmap = QPixmap.fromImage(image)
            self.scene.clear()  # 기존 그래프 제거
            self.scene.addPixmap(pixmap)
            self.graphicsView.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio)
        else:
            QMessageBox.warning(self, "경고", "그래프를 생성할 수 없습니다.")

    def extract_malware_name(self, data):
        """
        VirusTotal API 응답에서 악성코드 이름을 추출합니다.
        """
        try:
            if not data or 'data' not in data:
                return "정보 없음"

            analysis_results = data['data'].get('attributes', {}).get('last_analysis_results', {})
            malware_names = []
            for engine, result in analysis_results.items():
                category = result.get('category', '')
                result_str = result.get('result', '')
                if category == 'malicious' and result_str:
                    malware_names.append(result_str)
            if malware_names:
                return ", ".join(malware_names)
            else:
                return "정보 없음"
        except Exception as e:
            print(f"malware_name 추출 중 오류 발생: {e}")
            return "정보 없음"

    def extract_permalink(self, data):
        """
        VirusTotal API 응답에서 permalink를 추출합니다.
        (현재 사용되지 않으므로 필요 시 삭제 가능)
        """
        try:
            if not data or 'data' not in data:
                print("permalink 추출 실패: 'data' 키가 존재하지 않습니다.")
                return "URL 없음"
            attributes = data['data'].get('attributes', {})
            permalink = attributes.get('permalink', 'URL 없음')

            # 디버깅 출력
            print(f"Extracted permalink: {permalink}")

            return permalink
        except Exception as e:
            print(f"permalink 추출 중 오류 발생: {e}")
            return "URL 없음"

    def save_virustotal_results(self, vt_results):
        try:
            # 저장 경로 설정
            output_dir = "virustotal_results"
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, "virustotal_results.csv")

            # 결과 데이터를 DataFrame으로 변환 후 CSV로 저장
            rows = []
            for sha256, data in vt_results.items():
                if data and 'data' in data:
                    # Construct the URL based on SHA256
                    permalink = f"https://www.virustotal.com/gui/file/{sha256}"
                    rows.append({
                        'SHA256': sha256,
                        'VirusTotal Data': str(data.get('data', '조회 실패')),
                        'Malware Name': self.extract_malware_name(data),
                        'VirusTotal URL': permalink
                    })
                else:
                    rows.append({
                        'SHA256': sha256,
                        'VirusTotal Data': '조회 실패',
                        'Malware Name': '정보 없음',
                        'VirusTotal URL': 'URL 없음'
                    })

            df = pd.DataFrame(rows)
            df.to_csv(file_path, index=False, encoding="utf-8-sig")
            print(f"VirusTotal 검사 결과가 {file_path}에 저장되었습니다.")
        except Exception as e:
            print(f"VirusTotal 결과 저장 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"VirusTotal 결과 저장 중 오류가 발생했습니다: {e}")

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


def create_app():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()


if __name__ == "__main__":
    create_app()
