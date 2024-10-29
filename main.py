# main.py

from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QGraphicsView
from PyQt5.QtCore import QThread, pyqtSignal
import random
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from VirusTotal_API import VirusTotalAPI
from config import API_KEY
import os

# TensorFlow 경고 메시지 제거 (선택 사항)
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# plot_utils에서 plot_graph 함수 임포트
from plot_utils import plot_graph

class VirusTotalThread(QThread):
    hash_result = pyqtSignal(str, dict)
    finished = pyqtSignal(str)
    limit_exceeded = pyqtSignal()

    def __init__(self, api_key, md5_list):
        super().__init__()
        self.api_key = api_key
        self.md5_list = md5_list

    def run(self):
        vt_api = VirusTotalAPI(self.api_key)
        vt_results = vt_api.check_hashes_with_virustotal(self.md5_list)
        if vt_results is not None:
            for md5_hash, result in vt_results.items():
                if result is not None:
                    self.hash_result.emit(md5_hash, result)
                else:
                    self.hash_result.emit(md5_hash, {"error": "요청 실패"})
        if vt_results is None or len(vt_results) < len(self.md5_list):
            self.limit_exceeded.emit()
        else:
            self.finished.emit("바이러스 토탈 API 검사 완료")

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)

        # 위젯 참조
        self.status_virus_total = self.findChild(QtWidgets.QLabel, 'status_virus_total')
        self.vir_result = self.findChild(QtWidgets.QTableWidget, 'vir_result')
        self.train_result = self.findChild(QtWidgets.QTableWidget, 'train_result')
        self.confusion_matrix_result = self.findChild(QtWidgets.QTableWidget, 'confusion_matrix_result')
        self.preprocessing_result = self.findChild(QtWidgets.QTableWidget, 'preprocessing_result')
        self.train_button = self.findChild(QtWidgets.QPushButton, 'train_button')
        self.data_select = self.findChild(QtWidgets.QPushButton, 'data_select')
        self.normal_file = self.findChild(QtWidgets.QLineEdit, 'normal_file')
        self.malware_file = self.findChild(QtWidgets.QLineEdit, 'malware_file')
        self.graphicsView = self.findChild(QGraphicsView, 'graphicsView')

        # 위젯 초기화
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)
            self.status_virus_total.setText("바이러스 토탈 검사 중...")

        if self.vir_result:
            self.vir_result.setColumnCount(6)
            self.vir_result.setHorizontalHeaderLabels(['MD5', 'File Name', 'Type', 'Analysis Date', 'Summary', 'URL'])

        if self.train_result:
            self.train_result.setColumnCount(3)
            self.train_result.setHorizontalHeaderLabels(['Model', 'Accuracy', 'Malicious Count'])

        if self.train_button:
            self.train_button.clicked.connect(self.handle_train)

        if self.data_select:
            self.data_select.clicked.connect(self.select_malware_file)

        if self.normal_file:
            self.normal_file.setText('normal_pe (1).csv')

    def select_malware_file(self):
        malware_file, _ = QFileDialog.getOpenFileName(self, "악성 데이터 파일을 선택하세요", "", "CSV Files (*.csv)")
        if malware_file:
            if self.malware_file:
                self.malware_file.setText(malware_file)

    def handle_train(self):
        # 전처리 상태 표시
        if self.status_virus_total:
            self.status_virus_total.setText("전처리 중...")
            self.status_virus_total.setVisible(True)

        api_key = API_KEY
        normal_file = self.normal_file.text() if self.normal_file else ""
        malware_file = self.malware_file.text() if self.malware_file else ""
        ngram_file = 'ngram (1).csv'

        try:
            # 데이터 로드 및 전처리
            data_loader = DataLoader(normal_file, malware_file, ngram_file)
            pe_all = data_loader.load_data(load_malware=malware_file != "")

            preprocessor = DataPreprocessor(pe_all)
            preprocessor.filter_na()
            preprocessor.drop_columns(['filename', 'MD5', 'packer_type'])
            X, Y = preprocessor.get_features_and_labels()
            X = preprocessor.remove_constant_features(X)
            feature_selector = FeatureSelector(X, Y, k_features=10)
            X_new = pd.DataFrame(feature_selector.select_features(), columns=[f'Feature {i}' for i in range(1, 11)])

            # 전처리 완료 상태 업데이트
            if self.status_virus_total:
                self.status_virus_total.setText("전처리 완료")
                self.status_virus_total.setVisible(False)

            # 최종 선택된 10개 특성에 대한 요약 통계 계산
            summary_stats = X_new.describe(include='all').transpose()

            # 전처리 결과 요약 통계를 QTableWidget에 표시
            if self.preprocessing_result:
                self.preprocessing_result.setVisible(True)
                self.preprocessing_result.setRowCount(len(summary_stats.index))
                self.preprocessing_result.setColumnCount(len(summary_stats.columns))
                self.preprocessing_result.setHorizontalHeaderLabels(summary_stats.columns.tolist())
                self.preprocessing_result.setVerticalHeaderLabels(summary_stats.index.tolist())

                for row_idx, (index, row) in enumerate(summary_stats.iterrows()):
                    for col_idx, value in enumerate(row):
                        item = QtWidgets.QTableWidgetItem(str(value))
                        self.preprocessing_result.setItem(row_idx, col_idx, item)

            # 학습 시작
            classifier = Classifiers(X_new, Y)
            results = {
                'svm': classifier.do_svm(),
                'randomforest': classifier.do_randomforest(),
                'naivebayes': classifier.do_naivebayes(),
                'dnn': classifier.do_dnn(epochs=10)
            }
            self.display_training_results(results)
            self.display_confusion_matrices(results, Y)

            # 그래프 그리기 - plot_utils의 plot_graph 함수 호출
            accuracies = [result[0] for result in results.values()]
            model_names = list(results.keys())

            plot_graph(
                self.graphicsView,
                model_names,
                accuracies,
                title='Model Accuracy Comparison',
                xlabel='Model',
                ylabel='Accuracy',
                linestyle='-',  # 실선
                marker='o',      # 데이터 포인트 마커
                color='blue'     # 선 색상
            )

            # VirusTotal API 검사
            if 'MD5' in pe_all.columns and self.vir_result:
                malicious_md5 = pe_all.loc[pe_all['class'] == 1, 'MD5']
                md5_list = malicious_md5.tolist()

                if len(md5_list) > 10:
                    selected_md5_list = random.sample(md5_list, 10)
                else:
                    selected_md5_list = md5_list

                self.total_requests = len(selected_md5_list)
                self.completed_requests = 0

                self.vt_thread = VirusTotalThread(api_key, selected_md5_list)
                self.vt_thread.hash_result.connect(self.update_vir_result)
                self.vt_thread.finished.connect(self.on_vt_thread_finished)
                self.vt_thread.limit_exceeded.connect(self.on_limit_exceeded)
                self.vt_thread.start()
            else:
                print("MD5 칼럼이 데이터프레임에 없거나 vir_result 테이블을 찾을 수 없습니다.")

        except Exception as e:
            QMessageBox.critical(self, "오류", f"훈련 중 오류가 발생했습니다: {e}")

    def display_training_results(self, results):
        if not self.train_result:
            print("train_result 테이블을 찾을 수 없습니다.")
            return

        self.train_result.setRowCount(len(results) + 1)

        malicious_counts = {}
        for row, (model, (accuracy, predictions)) in enumerate(results.items()):
            count_malicious = (predictions == 1).sum()
            malicious_counts[model] = count_malicious

            self.train_result.setItem(row, 0, QtWidgets.QTableWidgetItem(model))
            self.train_result.setItem(row, 1, QtWidgets.QTableWidgetItem(f"{accuracy:.4f}"))
            self.train_result.setItem(row, 2, QtWidgets.QTableWidgetItem(str(count_malicious)))

        if malicious_counts:
            max_malicious_count = max(malicious_counts.values())
            best_models = [model for model, count in malicious_counts.items() if count == max_malicious_count]
            selected_model = best_models[0] if best_models else "N/A"

            self.train_result.setItem(len(results), 0, QtWidgets.QTableWidgetItem("Selected Model"))
            self.train_result.setItem(len(results), 1, QtWidgets.QTableWidgetItem(selected_model))
            self.train_result.setItem(len(results), 2, QtWidgets.QTableWidgetItem(str(max_malicious_count)))

    def display_confusion_matrices(self, results, Y_true):
        """
        혼돈 행렬을 생성하여 QTableWidget에 표시
        """
        if not self.confusion_matrix_result:
            print("confusion_matrix_result 테이블을 찾을 수 없습니다.")
            return

        self.confusion_matrix_result.clear()
        self.confusion_matrix_result.setRowCount(len(results) * 2)  # 모델 별로 행을 할당
        self.confusion_matrix_result.setColumnCount(3)
        self.confusion_matrix_result.setHorizontalHeaderLabels(['Model', 'Predicted: No', 'Predicted: Yes'])

        row_idx = 0
        for model_name, (accuracy, predictions) in results.items():
            cm = confusion_matrix(Y_true, predictions)
            if cm.shape == (2, 2):  # 이진 분류일 경우
                self.confusion_matrix_result.setItem(row_idx, 0, QtWidgets.QTableWidgetItem(f"{model_name} (Actual: No)"))
                self.confusion_matrix_result.setItem(row_idx, 1, QtWidgets.QTableWidgetItem(str(cm[0, 0])))
                self.confusion_matrix_result.setItem(row_idx, 2, QtWidgets.QTableWidgetItem(str(cm[0, 1])))

                row_idx += 1
                self.confusion_matrix_result.setItem(row_idx, 0, QtWidgets.QTableWidgetItem(f"{model_name} (Actual: Yes)"))
                self.confusion_matrix_result.setItem(row_idx, 1, QtWidgets.QTableWidgetItem(str(cm[1, 0])))
                self.confusion_matrix_result.setItem(row_idx, 2, QtWidgets.QTableWidgetItem(str(cm[1, 1])))
                row_idx += 1

    def update_vir_result(self, md5_hash, result):
        if not self.vir_result:
            print("vir_result 테이블을 찾을 수 없습니다.")
            return

        try:
            if "error" in result:
                file_name = "Error"
                file_type = "Error"
                last_analysis_date = "Error"
                analysis_summary = "Error"
                file_url = "Error"
            else:
                result_data = result.get("data", {}).get("attributes", {})
                names = result_data.get("names", [])
                file_name = names[0] if names else "Unknown"

                file_type = result_data.get("type_description", "Unknown")
                last_analysis_date = result_data.get("last_analysis_date", "N/A")
                analysis_stats = result_data.get("last_analysis_stats", {})
                malicious_count = analysis_stats.get("malicious", 0)
                harmless_count = analysis_stats.get("harmless", 0)
                analysis_summary = f"Malicious: {malicious_count}, Harmless: {harmless_count}"

                file_url = result.get("data", {}).get("links", {}).get("self", "N/A")

            current_row = self.vir_result.rowCount()
            self.vir_result.insertRow(current_row)
            self.vir_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem(md5_hash))
            self.vir_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem(file_name))
            self.vir_result.setItem(current_row, 2, QtWidgets.QTableWidgetItem(file_type))
            self.vir_result.setItem(current_row, 3, QtWidgets.QTableWidgetItem(str(last_analysis_date)))
            self.vir_result.setItem(current_row, 4, QtWidgets.QTableWidgetItem(analysis_summary))
            self.vir_result.setItem(current_row, 5, QtWidgets.QTableWidgetItem(file_url))

        except Exception as e:
            print(f"Error parsing result for {md5_hash}: {e}")
            current_row = self.vir_result.rowCount()
            self.vir_result.insertRow(current_row)
            self.vir_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem(md5_hash))
            self.vir_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem("Error parsing result"))

    def on_vt_thread_finished(self, message):
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText(message)
        msg_box.setWindowTitle("검사 완료")
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()

    def on_limit_exceeded(self):
        QMessageBox.warning(self, "요청 한도 초과", "바이러스 토탈 API 요청 한도를 초과했습니다.")
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)

def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()

if __name__ == "__main__":
    create_file_selector()
