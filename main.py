from PyQt5 import uic, QtWidgets
<<<<<<< HEAD
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QGraphicsView
=======
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
>>>>>>> fc44e4afec71f75226f0f89528c359047da33988
from PyQt5.QtCore import QThread, pyqtSignal
import random
import pandas as pd
import numpy as np
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from VirusTotal_API import VirusTotalAPI
from config import API_KEY
<<<<<<< HEAD
import os

# TensorFlow 경고 메시지 제거 (선택 사항)
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# plot_utils에서 plot_graph 함수 임포트
from plot_utils import plot_graph

class VirusTotalThread(QThread):
    hash_result = pyqtSignal(str, dict)
    finished = pyqtSignal(str)
    limit_exceeded = pyqtSignal()
=======
import time


class VirusTotalThread(QThread):
    hash_result = pyqtSignal(str, dict)
    progress_update = pyqtSignal(str)
    finished = pyqtSignal(str)
>>>>>>> fc44e4afec71f75226f0f89528c359047da33988

    def __init__(self, api_key, md5_list):
        super().__init__()
        self.api_key = api_key
        self.md5_list = md5_list

    def run(self):
<<<<<<< HEAD
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
=======
        try:
            vt_api = VirusTotalAPI(self.api_key)
            total = len(self.md5_list)

            for i, md5_hash in enumerate(self.md5_list, 1):
                try:
                    self.progress_update.emit(f"검사 진행중... ({i}/{total})")
                    result = vt_api.check_hashes_with_virustotal([md5_hash])
                    if md5_hash in result:
                        self.hash_result.emit(md5_hash, result[md5_hash])
                    else:
                        self.hash_result.emit(md5_hash, {"error": "No result returned"})
                    time.sleep(1)
                except Exception as e:
                    self.hash_result.emit(md5_hash, {"error": str(e)})

            self.finished.emit("VirusTotal 검사 완료")
        except Exception as e:
            self.finished.emit(f"검사 중 오류 발생: {str(e)}")

>>>>>>> fc44e4afec71f75226f0f89528c359047da33988

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)

<<<<<<< HEAD
        # 위젯 참조
        self.status_virus_total = self.findChild(QtWidgets.QLabel, 'status_virus_total')
        self.vir_result = self.findChild(QtWidgets.QTableWidget, 'vir_result')
        self.train_result = self.findChild(QtWidgets.QTableWidget, 'train_result')
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
        if self.status_virus_total:
            self.status_virus_total.setText("전처리 중...")
            self.status_virus_total.setVisible(True)

        api_key = API_KEY
        normal_file = self.normal_file.text() if self.normal_file else ""
        malware_file = self.malware_file.text() if self.malware_file else ""
        ngram_file = 'ngram (1).csv'

        try:
            data_loader = DataLoader(normal_file, malware_file, ngram_file)
            pe_all = data_loader.load_data(load_malware=malware_file != "")

            preprocessor = DataPreprocessor(pe_all)
            preprocessor.filter_na()
            preprocessor.drop_columns(['filename', 'MD5', 'packer_type'])
            X, Y = preprocessor.get_features_and_labels()
            X = preprocessor.remove_constant_features(X)
            feature_selector = FeatureSelector(X, Y, k_features=10)
            X_new = pd.DataFrame(feature_selector.select_features(), columns=[f'Feature {i}' for i in range(1, 11)])

            if self.status_virus_total:
                self.status_virus_total.setText("전처리 완료")
                self.status_virus_total.setVisible(False)

            # 전처리된 데이터의 첫 50개 행을 표시하도록 수정
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

            classifier = Classifiers(X_new, Y)
            results = {
                'svm': classifier.do_svm(),
                'randomforest': classifier.do_randomforest(),
                'naivebayes': classifier.do_naivebayes(),
                'dnn': classifier.do_dnn(epochs=50)
            }
            self.display_training_results(results)

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
=======
        self.setup_initial_ui()
        self.setup_connections()

    def setup_initial_ui(self):
        # 기본 파일 설정
        self.normal_file = 'normal_pe (1).csv'
        self.nomal_file.setText(self.normal_file)

        # 전처리 결과 테이블 설정
        self.preprocessing_result.setColumnCount(8)
        self.preprocessing_result.setHorizontalHeaderLabels([
            '통계', 'count', 'mean', 'std', 'min', '25%', '50%', '75%', 'max'
        ])

        # 학습 결과 테이블 설정
        self.training_result.setColumnCount(3)
        self.training_result.setHorizontalHeaderLabels([
            '모델', '정확도', '악성코드 탐지'
        ])

        # VirusTotal 결과 테이블 설정
        self.vt_result.setColumnCount(4)
        self.vt_result.setHorizontalHeaderLabels([
            'MD5', '파일명', '악성 탐지', '분석 날짜'
        ])

        # 초기 상태 설정
        self.update_all_status("대기중")

    def setup_connections(self):
        self.data_select.clicked.connect(self.select_malware_file)
        self.train_button.clicked.connect(self.handle_train)

    def update_all_status(self, status):
        """모든 상태 레이블 업데이트"""
        for widget in ["preprocessing_status", "training_status", "vt_status"]:
            getattr(self, widget).setText(f"상태: {status}")

    def select_malware_file(self):
        """악성코드 파일 선택"""
        malware_file, _ = QFileDialog.getOpenFileName(
            self,
            "악성 데이터 파일을 선택하세요",
            "",
            "CSV Files (*.csv)"
        )
        if malware_file:
            self.malware_file.setText(malware_file)

    def handle_train(self):
        """분석 시작"""
        # 초기화
        self.clear_all_results()

        try:
            # 1. 데이터 전처리 단계
            self.handle_preprocessing()

            # 2. 모델 학습 단계
            self.handle_training()

            # 3. VirusTotal 검사 단계
            self.handle_virustotal()

        except Exception as e:
            QMessageBox.critical(self, "오류", f"분석 중 오류가 발생했습니다: {str(e)}")

    def clear_all_results(self):
        """모든 결과 초기화"""
        # 텍스트 영역 초기화
        for widget in [self.preprocessing_text, self.training_text, self.vt_text]:
            widget.clear()

        # 테이블 초기화
        for table in [self.preprocessing_result, self.training_result, self.vt_result]:
            table.setRowCount(0)

        # 상태 초기화
        self.update_all_status("대기중")

    def handle_preprocessing(self):
        """데이터 전처리 처리"""
        self.preprocessing_status.setText("상태: 처리중")
        self.preprocessing_text.append("데이터 로딩 및 전처리 시작...")

        # 데이터 로딩
        data_loader = DataLoader(self.normal_file, self.malware_file.text(), 'ngram (1).csv')
        self.pe_all = data_loader.load_data()

        # 전처리
        preprocessor = DataPreprocessor(self.pe_all)
        preprocessor.filter_na()
        preprocessor.drop_columns(['filename', 'MD5', 'packer_type'])
        X, Y = preprocessor.get_features_and_labels()
        X = preprocessor.remove_constant_features(X)

        feature_selector = FeatureSelector(X, Y)
        self.X_new = feature_selector.select_features()
        self.Y = Y

        # 결과 표시
        stats = pd.DataFrame(self.X_new).describe()
        self.display_preprocessing_results(stats)

        self.preprocessing_status.setText("상태: 완료")
        self.preprocessing_text.append("전처리 완료")

    def handle_training(self):
        """모델 학습 처리"""
        self.training_status.setText("상태: 처리중")
        self.training_text.append("모델 학습 시작...")

        classifier = Classifiers(self.X_new, self.Y)
        models = {
            'SVM': classifier.do_svm,
            'Random Forest': classifier.do_randomforest,
            'Naive Bayes': classifier.do_naivebayes,
            'DNN': lambda: classifier.do_dnn(epochs=10)
        }

        for name, func in models.items():
            self.training_text.append(f"{name} 모델 학습 중...")
            accuracy, predictions = func()
            malicious_count = (predictions == 1).sum()

            # 결과를 테이블에 추가
            current_row = self.training_result.rowCount()
            self.training_result.insertRow(current_row)
            self.training_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem(name))
            self.training_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem(f"{accuracy:.4f}"))
            self.training_result.setItem(current_row, 2, QtWidgets.QTableWidgetItem(str(malicious_count)))

        self.training_status.setText("상태: 완료")
        self.training_text.append("모델 학습 완료")

    def handle_virustotal(self):
        """VirusTotal 검사 처리"""
        if 'MD5' not in self.pe_all.columns:
            self.vt_text.append("MD5 해시 정보가 없습니다.")
            return

        self.vt_status.setText("상태: 처리중")
        self.vt_text.append("VirusTotal 검사 시작...")

        malicious_md5 = self.pe_all.loc[self.pe_all['class'] == 1, 'MD5']
        md5_list = malicious_md5.tolist()[:10]  # 10개로 제한

        self.vt_thread = VirusTotalThread(API_KEY, md5_list)
        self.vt_thread.hash_result.connect(self.update_vt_result)
        self.vt_thread.progress_update.connect(lambda x: self.vt_text.append(x))
        self.vt_thread.finished.connect(self.handle_vt_finished)
        self.vt_thread.start()

    def display_preprocessing_results(self, stats):
        """전처리 결과를 테이블에 표시"""
        self.preprocessing_result.setRowCount(len(stats.index))

        for row, stat_name in enumerate(stats.index):
            self.preprocessing_result.setItem(row, 0, QtWidgets.QTableWidgetItem(str(stat_name)))
            for col, value in enumerate(stats.loc[stat_name]):
                # 숫자값을 문자열로 변환할 때 타입을 체크
                if isinstance(value, (int, float)):
                    formatted_value = f"{value:.4f}"
                else:
                    formatted_value = str(value)
                self.preprocessing_result.setItem(row, col + 1, QtWidgets.QTableWidgetItem(formatted_value))

    def update_vt_result(self, md5_hash, result):
        """VirusTotal 검사 결과 업데이트"""
        try:
            if "error" in result:
                current_row = self.vt_result.rowCount()
                self.vt_result.insertRow(current_row)
                self.vt_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem(md5_hash))
                self.vt_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem("N/A"))
                self.vt_result.setItem(current_row, 2, QtWidgets.QTableWidgetItem("Error"))
                self.vt_result.setItem(current_row, 3, QtWidgets.QTableWidgetItem(str(result["error"])))
                return

            result_data = result.get("data", {}).get("attributes", {})
            names = result_data.get("names", [])
            file_name = names[0] if names else "Unknown"

            analysis_stats = result_data.get("last_analysis_stats", {})
            malicious_count = analysis_stats.get("malicious", 0)
            last_analysis_date = result_data.get("last_analysis_date", "N/A")

            current_row = self.vt_result.rowCount()
            self.vt_result.insertRow(current_row)

            self.vt_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem(md5_hash))
            self.vt_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem(file_name))
            self.vt_result.setItem(current_row, 2, QtWidgets.QTableWidgetItem(f"{malicious_count}개의 엔진이 악성으로 탐지"))
            self.vt_result.setItem(current_row, 3, QtWidgets.QTableWidgetItem(str(last_analysis_date)))

        except Exception as e:
            self.vt_text.append(f"Error parsing result for {md5_hash}: {str(e)}")

    def handle_vt_finished(self, message):
        """VirusTotal 검사 완료 처리"""
        self.vt_status.setText("상태: 완료")
        self.vt_text.append(message)
        QMessageBox.information(self, "완료", message)
>>>>>>> fc44e4afec71f75226f0f89528c359047da33988

    def on_limit_exceeded(self):
        QMessageBox.warning(self, "요청 한도 초과", "바이러스 토탈 API 요청 한도를 초과했습니다.")
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)

def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()

<<<<<<< HEAD
=======

>>>>>>> fc44e4afec71f75226f0f89528c359047da33988
if __name__ == "__main__":
    create_file_selector()