# -*- coding: utf-8 -*-
from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QGraphicsView
from PyQt5.QtCore import QThread, pyqtSignal
import random
import pandas as pd
import numpy as np
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from VirusTotal_API import VirusTotalAPI
import os

# TensorFlow 경고 메시지 제거 (선택 사항)
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# plot_utils에서 plot_graph 함수 임포트
from plot_utils import plot_graph

class VirusTotalThread(QThread):
    hash_result = pyqtSignal(str, dict, str)  # 해시 타입 추가
    finished = pyqtSignal(str)
    limit_exceeded = pyqtSignal()
    invalid_api_key = pyqtSignal()

    def __init__(self, api_key, hash_list, hash_type='MD5'):
        super().__init__()
        self.api_key = api_key
        self.hash_list = hash_list
        self.hash_type = hash_type  # 'MD5' 또는 'sha256'

    def run(self):
        vt_api = VirusTotalAPI(self.api_key)
        try:
            vt_results = vt_api.check_hashes_with_virustotal(self.hash_list, self.hash_type)
        except Exception as e:
            print(f"API 호출 중 예외 발생: {e}")
            self.invalid_api_key.emit()
            return

        if isinstance(vt_results, dict) and vt_results.get("invalid_api_key"):
            self.invalid_api_key.emit()
            return

        for hash_val, result in vt_results.items():
            if result is not None:
                self.hash_result.emit(hash_val, result, self.hash_type)
            else:
                self.hash_result.emit(hash_val, {"error": "요청 실패"}, self.hash_type)

        if len(vt_results) < len(self.hash_list):
            self.limit_exceeded.emit()
        else:
            self.finished.emit(f"{self.hash_type} 검사 완료")

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)

        # 위젯 참조
        self.status_data_preprocessing = self.findChild(QtWidgets.QLabel, 'status_data_preprocessing')
        self.status_model_training = self.findChild(QtWidgets.QLabel, 'status_model_training')
        self.status_virus_total = self.findChild(QtWidgets.QLabel, 'status_virus_total')  # 여전히 존재하나 UI에서 제거됨
        self.vir_result = self.findChild(QtWidgets.QTableWidget, 'vir_result')
        self.train_result = self.findChild(QtWidgets.QTableWidget, 'train_result')
        self.preprocessing_result = self.findChild(QtWidgets.QTableWidget, 'preprocessing_result')
        self.train_button = self.findChild(QtWidgets.QPushButton, 'train_button')
        self.data_select = self.findChild(QtWidgets.QPushButton, 'data_select')
        self.normal_file = self.findChild(QtWidgets.QLineEdit, 'normal_file')
        self.malware_file = self.findChild(QtWidgets.QLineEdit, 'malware_file')
        self.graphicsView = self.findChild(QGraphicsView, 'graphicsView')
        self.api_key_input = self.findChild(QtWidgets.QLineEdit, 'api_key_input')  # API 키 입력 필드 참조

        # 위젯 초기화
        if self.status_data_preprocessing:
            self.status_data_preprocessing.setText("대기 중")
        if self.status_model_training:
            self.status_model_training.setText("대기 중")
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)
            self.status_virus_total.setText("대기 중")  # UI에서 제거되었으므로 추후 필요 시 삭제

        if self.vir_result:
            self.vir_result.setColumnCount(7)  # 7개 칼럼
            self.vir_result.setHorizontalHeaderLabels(['MD5', 'SHA256', 'File Name', 'Type', 'Analysis Date', 'Summary', 'URL'])

        if self.train_result:
            self.train_result.setColumnCount(4)
            self.train_result.setHorizontalHeaderLabels(['Model', 'Accuracy', 'Malicious Count', 'Benign Count'])

        if self.preprocessing_result:
            self.preprocessing_result.setVisible(False)  # 초기에는 숨김

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
        print("훈련 시작")
        # 전처리 상태 업데이트
        if self.status_data_preprocessing:
            self.status_data_preprocessing.setText("전처리 중...")

        # API 키 가져오기
        api_key = self.api_key_input.text().strip() if self.api_key_input else ""
        print(f"API 키: {api_key}")
        if not api_key:
            QMessageBox.warning(self, "API 키 누락", "바이러스 토탈 API 키를 입력하세요.")
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("대기 중")
            return

        normal_file = self.normal_file.text() if self.normal_file else ""
        malware_file = self.malware_file.text() if self.malware_file else ""
        ngram_file = 'ngram (1).csv'
        print(f"파일 경로 - 정상: {normal_file}, 악성: {malware_file}, ngram: {ngram_file}")

        try:
            data_loader = DataLoader(normal_file, malware_file, ngram_file)
            pe_all = data_loader.load_data(load_malware=malware_file != "")
            print("데이터 로딩 완료")

            preprocessor = DataPreprocessor(pe_all)
            preprocessor.filter_na()
            preprocessor.drop_columns(['filename', 'packer_type'])  # 'MD5' 유지
            X, Y = preprocessor.get_features_and_labels()
            X = preprocessor.remove_constant_features(X)
            feature_selector = FeatureSelector(X, Y, k_features=10)
            X_new = pd.DataFrame(feature_selector.select_features(), columns=[f'Feature {i}' for i in range(1, 11)])
            print("데이터 전처리 및 특징 선택 완료")

            # 전처리 완료 상태 업데이트
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("전처리 완료")

            # 전처리된 데이터의 첫 50개 행을 표시
            preprocessed_data_to_display = X_new.head(50)

            if self.preprocessing_result:
                self.preprocessing_result.setVisible(True)
                self.preprocessing_result.setRowCount(len(preprocessed_data_to_display))
                self.preprocessing_result.setColumnCount(len(preprocessed_data_to_display.columns))
                self.preprocessing_result.setHorizontalHeaderLabels(preprocessed_data_to_display.columns.tolist())
                self.preprocessing_result.setVerticalHeaderLabels([str(i) for i in preprocessed_data_to_display.index])

                for row_idx, row in preprocessed_data_to_display.iterrows():
                    for col_idx, value in enumerate(row):
                        item = QtWidgets.QTableWidgetItem(str(value))
                        self.preprocessing_result.setItem(row_idx, col_idx, item)

            # 모델 학습 상태 업데이트
            if self.status_model_training:
                self.status_model_training.setText("모델 학습 중...")

            # 모델 학습
            classifier = Classifiers(X_new, Y)
            results = {
                'svm': classifier.do_svm(),
                'randomforest': classifier.do_randomforest(),
                'naivebayes': classifier.do_naivebayes(),
                'dnn': classifier.do_dnn(epochs=50)
            }
            print("모델 학습 완료")
            self.display_training_results(results)

            accuracies = [result[0] for result in results.values()]
            model_names = list(results.keys())

            plot_graph(
                self.graphicsView,
                model_names,
                accuracies,
                title='모델 정확도 비교',
                xlabel='모델',
                ylabel='정확도',
                linestyle='-',  # 실선
                marker='o',      # 데이터 포인트 마커
                color='blue'     # 선 색상
            )
            print("그래프 그리기 완료")

            # 모델 학습 완료 상태 업데이트
            if self.status_model_training:
                self.status_model_training.setText("모델 학습 완료")

            # 바이러스 토탈 검사 시작
            if 'MD5' in pe_all.columns and 'sha256' in pe_all.columns and self.vir_result:
                malicious_md5 = pe_all.loc[pe_all['class'] == 1, 'MD5']
                malicious_sha256 = pe_all.loc[pe_all['class'] == 1, 'sha256']

                md5_list = malicious_md5.tolist()
                sha256_list = malicious_sha256.tolist()

                # 샘플링 (10개 이하일 경우 전체 사용)
                if len(md5_list) > 10:
                    selected_md5_list = random.sample(md5_list, 10)
                else:
                    selected_md5_list = md5_list

                if len(sha256_list) > 10:
                    selected_sha256_list = random.sample(sha256_list, 10)
                else:
                    selected_sha256_list = sha256_list

                print(f"MD5 샘플: {selected_md5_list}")
                print(f"SHA256 샘플: {selected_sha256_list}")

                # MD5 검사 스레드 시작
                self.vt_thread_md5 = VirusTotalThread(api_key, selected_md5_list, hash_type='MD5')
                self.vt_thread_md5.hash_result.connect(lambda hash_val, res, ht: self.update_vir_result(hash_val, res, ht))
                self.vt_thread_md5.finished.connect(self.on_vt_thread_finished)
                self.vt_thread_md5.limit_exceeded.connect(self.on_limit_exceeded)
                self.vt_thread_md5.invalid_api_key.connect(self.on_invalid_api_key)
                self.vt_thread_md5.start()
                print("MD5 검사 스레드 시작")

                # SHA256 검사 스레드 시작
                self.vt_thread_sha256 = VirusTotalThread(api_key, selected_sha256_list, hash_type='sha256')
                self.vt_thread_sha256.hash_result.connect(lambda hash_val, res, ht: self.update_vir_result(hash_val, res, ht))
                self.vt_thread_sha256.finished.connect(self.on_vt_thread_finished)
                self.vt_thread_sha256.limit_exceeded.connect(self.on_limit_exceeded)
                self.vt_thread_sha256.invalid_api_key.connect(self.on_invalid_api_key)
                self.vt_thread_sha256.start()
                print("SHA256 검사 스레드 시작")
            else:
                print("필요한 칼럼이 데이터프레임에 없거나 vir_result 테이블을 찾을 수 없습니다.")

        except Exception as e:
            print(f"훈련 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"훈련 중 오류가 발생했습니다: {e}")
            if self.status_data_preprocessing:
                self.status_data_preprocessing.setText("대기 중")
            if self.status_model_training:
                self.status_model_training.setText("대기 중")

    def display_training_results(self, results):
        if not self.train_result:
            print("train_result 테이블을 찾을 수 없습니다.")
            return

        self.train_result.setColumnCount(4)
        self.train_result.setHorizontalHeaderLabels(['Model', 'Accuracy', 'Malicious Count', 'Benign Count'])
        self.train_result.setRowCount(len(results) + 1)

        malicious_counts = {}
        benign_counts = {}
        for row, (model, (accuracy, predictions)) in enumerate(results.items()):
            count_malicious = (predictions == 1).sum()
            count_benign = (predictions == 0).sum()
            malicious_counts[model] = count_malicious
            benign_counts[model] = count_benign

            self.train_result.setItem(row, 0, QtWidgets.QTableWidgetItem(model))
            self.train_result.setItem(row, 1, QtWidgets.QTableWidgetItem(f"{accuracy:.4f}"))
            self.train_result.setItem(row, 2, QtWidgets.QTableWidgetItem(str(count_malicious)))
            self.train_result.setItem(row, 3, QtWidgets.QTableWidgetItem(str(count_benign)))

        if malicious_counts:
            max_malicious_count = max(malicious_counts.values())
            best_models = [model for model, count in malicious_counts.items() if count == max_malicious_count]
            selected_model = best_models[0] if best_models else "N/A"

            self.train_result.setItem(len(results), 0, QtWidgets.QTableWidgetItem("Selected Model"))
            self.train_result.setItem(len(results), 1, QtWidgets.QTableWidgetItem(selected_model))
            self.train_result.setItem(len(results), 2, QtWidgets.QTableWidgetItem(str(max_malicious_count)))
            if benign_counts:
                max_benign_count = max(benign_counts.values())
                self.train_result.setItem(len(results), 3, QtWidgets.QTableWidgetItem(str(max_benign_count)))

    def update_vir_result(self, hash_val, result, hash_type='MD5'):
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

        except Exception as e:
            print(f"Error parsing result for {hash_val}: {e}")
            file_name = "Error"
            file_type = "Error"
            last_analysis_date = "Error"
            analysis_summary = "Error"
            file_url = "Error"

        # 기존 MD5 또는 SHA256 결과를 업데이트
        # 각 해시 타입별로 별도의 열을 업데이트

        # 먼저, 현재 테이블의 모든 행을 확인하여 이미 존재하는 MD5 또는 SHA256인지 확인
        row_found = False
        for row in range(self.vir_result.rowCount()):
            existing_md5_item = self.vir_result.item(row, 0)
            existing_sha256_item = self.vir_result.item(row, 1)
            existing_md5 = existing_md5_item.text() if existing_md5_item else ""
            existing_sha256 = existing_sha256_item.text() if existing_sha256_item else ""
            if (hash_type == 'MD5' and existing_md5 == hash_val) or (hash_type == 'sha256' and existing_sha256 == hash_val):
                # 이미 존재하는 해시의 경우 업데이트
                self.vir_result.setItem(row, 2, QtWidgets.QTableWidgetItem(file_name))
                self.vir_result.setItem(row, 3, QtWidgets.QTableWidgetItem(file_type))
                self.vir_result.setItem(row, 4, QtWidgets.QTableWidgetItem(str(last_analysis_date)))
                self.vir_result.setItem(row, 5, QtWidgets.QTableWidgetItem(analysis_summary))
                self.vir_result.setItem(row, 6, QtWidgets.QTableWidgetItem(file_url))
                row_found = True
                break

        if not row_found:
            # 새로운 행 추가
            current_row = self.vir_result.rowCount()
            self.vir_result.insertRow(current_row)
            if hash_type == 'MD5':
                self.vir_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem(hash_val))
                self.vir_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem("N/A"))  # SHA256 미사용 시
            elif hash_type == 'sha256':
                self.vir_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem("N/A"))  # MD5 미사용 시
                self.vir_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem(hash_val))
            self.vir_result.setItem(current_row, 2, QtWidgets.QTableWidgetItem(file_name))
            self.vir_result.setItem(current_row, 3, QtWidgets.QTableWidgetItem(file_type))
            self.vir_result.setItem(current_row, 4, QtWidgets.QTableWidgetItem(str(last_analysis_date)))
            self.vir_result.setItem(current_row, 5, QtWidgets.QTableWidgetItem(analysis_summary))
            self.vir_result.setItem(current_row, 6, QtWidgets.QTableWidgetItem(file_url))
            print(f"새로운 결과 추가 - {hash_type}: {hash_val}")

    def on_vt_thread_finished(self, message):
        # 바이러스 토탈 검사 완료 시 상태 레이블 숨기기
        # "VirusTotal 검사" 레이블이 제거되었으므로 관련 코드도 삭제
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText(message)
        msg_box.setWindowTitle("검사 완료")
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()
        print(f"{message} 완료")

    def on_limit_exceeded(self):
        QMessageBox.warning(self, "요청 한도 초과", "바이러스 토탈 API 요청 한도를 초과했습니다.")
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)
        print("요청 한도 초과")

    def on_invalid_api_key(self):
        QMessageBox.critical(self, "유효하지 않은 API 키", "입력한 바이러스 토탈 API 키가 유효하지 않습니다.")
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)
        print("유효하지 않은 API 키")

def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()

if __name__ == "__main__":
    create_file_selector()
