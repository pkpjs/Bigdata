import sys
import os
from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QMessageBox, QGraphicsView,
    QInputDialog, QLineEdit, QAction
)
from PyQt5.QtCore import QThread, pyqtSignal
import random
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from VirusTotal_API import VirusTotalAPI
from cryptography.fernet import Fernet

# TensorFlow 경고 메시지 제거 (선택 사항)
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# plot_utils에서 plot_graph 함수 임포트
from plot_utils import plot_graph

def generate_key():
    """새로운 암호화 키를 생성하여 secret.key 파일에 저장"""
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)
    print("암호화 키가 생성되어 'secret.key' 파일에 저장되었습니다.")

def load_key():
    """암호화 키를 파일에서 로드"""
    key_path = 'secret.key'
    if not os.path.exists(key_path):
        generate_key()
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
    return key

def save_api_key(api_key, cipher_suite):
    """API 키를 암호화하여 저장하기"""
    if api_key:
        encrypted_api_key = cipher_suite.encrypt(api_key.encode()).decode()
        with open('api_key.enc', 'w') as enc_file:
            enc_file.write(encrypted_api_key)
        print("암호화된 API 키가 'api_key.enc' 파일에 저장되었습니다.")
    else:
        print("빈 API 키는 저장할 수 없습니다.")

def load_api_key_from_file(cipher_suite):
    """암호화된 API 키를 복호화하여 로드하기"""
    enc_file_path = 'api_key.enc'
    if os.path.exists(enc_file_path):
        with open(enc_file_path, 'r') as enc_file:
            encrypted_api_key = enc_file.read()
        try:
            decrypted_api_key = cipher_suite.decrypt(encrypted_api_key.encode()).decode()
            if decrypted_api_key:
                print("API 키가 성공적으로 복호화되었습니다.")
                return decrypted_api_key
            else:
                print("복호화된 API 키가 비어 있습니다.")
                return None
        except Exception as e:
            print(f"API 키 복호화 실패: {e}")
            return None
    else:
        print("'api_key.enc' 파일이 존재하지 않습니다.")
        return None

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

        # 암호화 키 로드
        try:
            self.key = load_key()
            self.cipher_suite = Fernet(self.key)
        except Exception as e:
            QMessageBox.critical(self, "오류", f"암호화 키 로드/생성 중 오류가 발생했습니다: {e}")
            sys.exit(1)

        # 위젯 참조
        self.status_virus_total = self.findChild(QtWidgets.QLabel, 'status_virus_total')
        self.vir_result = self.findChild(QtWidgets.QTableWidget, 'vir_result')
        self.train_result = self.findChild(QtWidgets.QTableWidget, 'train_result')
        self.confusion_matrix_result = self.findChild(QtWidgets.QTableWidget, 'confusion_matrix_result')
        self.preprocessing_result = self.findChild(QtWidgets.QTableWidget, 'preprocessing_result')
        self.train_button = self.findChild(QtWidgets.QPushButton, 'train_button')
        self.data_select = self.findChild(QtWidgets.QPushButton, 'data_select')
        self.normal_file = self.findChild(QLineEdit, 'normal_file')
        self.malware_file = self.findChild(QLineEdit, 'malware_file')
        self.graphicsView = self.findChild(QGraphicsView, 'graphicsView')

        # 위젯 초기화
        if self.status_virus_total:
            self.status_virus_total.setVisible(False)
            self.status_virus_total.setText("바이러스 토탈 검사 중...")

        if self.vir_result:
            self.vir_result.setColumnCount(6)
            self.vir_result.setHorizontalHeaderLabels(['MD5', '파일 이름', '유형', '분석 날짜', '요약', 'URL'])

        if self.train_result:
            self.train_result.setColumnCount(4)
            self.train_result.setHorizontalHeaderLabels(['모델', '정확도', '악성 개수', '양성 개수'])

        if self.confusion_matrix_result:
            self.confusion_matrix_result.setColumnCount(3)
            self.confusion_matrix_result.setHorizontalHeaderLabels(['모델', '예측: 아니오', '예측: 예'])

        if self.preprocessing_result:
            self.preprocessing_result.setVisible(False)  # 초기에는 숨김

        if self.train_button:
            self.train_button.clicked.connect(self.handle_train)

        if self.data_select:
            self.data_select.clicked.connect(self.select_malware_file)

        if self.normal_file:
            self.normal_file.setText('normal_pe (1).csv')

        # API 키를 저장할 변수 초기화
        self.api_key = None

        # 저장된 API 키 불러오기
        self.api_key = load_api_key_from_file(self.cipher_suite)

        # API 키가 없으면 사용자에게 입력 받기
        if not self.api_key:
            self.prompt_for_api_key()

        # 메뉴 바에 설정 메뉴 추가 (API 키 변경 기능 추가)
        menubar = self.menuBar()
        settings_menu = menubar.addMenu('설정')

        change_api_key_action = QAction('API 키 변경', self)
        change_api_key_action.triggered.connect(self.change_api_key)
        settings_menu.addAction(change_api_key_action)

    def prompt_for_api_key(self):
        """사용자에게 API 키 입력을 요청하고 저장"""
        while True:
            self.api_key, ok = QInputDialog.getText(
                self,
                "API 키 입력",
                "바이러스 토탈 API 키를 입력하세요:",
                QLineEdit.Password  # 보안을 위해 입력 내용을 숨김
            )
            if ok:
                self.api_key = self.api_key.strip()
                if self.api_key:
                    # 입력받은 API 키 저장
                    save_api_key(self.api_key, self.cipher_suite)
                    QMessageBox.information(self, "성공", "API 키가 성공적으로 저장되었습니다.")
                    break
                else:
                    QMessageBox.warning(self, "입력 오류", "API 키는 비어 있을 수 없습니다. 다시 입력하세요.")
            else:
                QMessageBox.warning(self, "취소됨", "API 키 입력이 취소되었습니다.")
                # 애플리케이션을 종료하거나 기본 동작을 설정할 수 있습니다.
                sys.exit(1)

    def change_api_key(self):
        """메뉴에서 API 키 변경하기"""
        while True:
            new_api_key, ok = QInputDialog.getText(
                self,
                "API 키 변경",
                "새로운 바이러스 토탈 API 키를 입력하세요:",
                QLineEdit.Password
            )
            if ok:
                new_api_key = new_api_key.strip()
                if new_api_key:
                    self.api_key = new_api_key
                    save_api_key(self.api_key, self.cipher_suite)
                    QMessageBox.information(self, "성공", "API 키가 성공적으로 변경되었습니다.")
                    break
                else:
                    QMessageBox.warning(self, "입력 오류", "API 키는 비어 있을 수 없습니다. 다시 입력하세요.")
            else:
                QMessageBox.warning(self, "취소됨", "API 키 변경이 취소되었습니다.")
                break

    def select_malware_file(self):
        """악성 데이터 파일 선택"""
        malware_file, _ = QFileDialog.getOpenFileName(self, "악성 데이터 파일을 선택하세요", "", "CSV Files (*.csv)")
        if malware_file:
            if self.malware_file:
                self.malware_file.setText(malware_file)

    def handle_train(self):
        """훈련 버튼 클릭 시 처리 로직"""
        if self.status_virus_total:
            self.status_virus_total.setText("전처리 중...")
            self.status_virus_total.setVisible(True)

        # API 키가 입력되지 않은 경우 사용자에게 입력 받기
        if not self.api_key:
            self.prompt_for_api_key()
            if not self.api_key:
                QMessageBox.warning(self, "API 키 필요", "바이러스 토탈 API 키가 필요합니다.")
                if self.status_virus_total:
                    self.status_virus_total.setVisible(False)
                return

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

            classifier = Classifiers(X_new, Y)
            results = {
                'svm': classifier.do_svm(),
                'randomforest': classifier.do_randomforest(),
                'naivebayes': classifier.do_naivebayes(),
                'dnn': classifier.do_dnn(epochs=50)
            }
            self.display_training_results(results)
            self.display_confusion_matrices(results, Y)

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

            if 'MD5' in pe_all.columns and self.vir_result:
                malicious_md5 = pe_all.loc[pe_all['class'] == 1, 'MD5']
                md5_list = malicious_md5.tolist()

                if len(md5_list) > 10:
                    selected_md5_list = random.sample(md5_list, 10)
                else:
                    selected_md5_list = md5_list

                self.total_requests = len(selected_md5_list)
                self.completed_requests = 0

                self.vt_thread = VirusTotalThread(self.api_key, selected_md5_list)
                self.vt_thread.hash_result.connect(self.update_vir_result)
                self.vt_thread.finished.connect(self.on_vt_thread_finished)
                self.vt_thread.limit_exceeded.connect(self.on_limit_exceeded)
                self.vt_thread.start()
            else:
                print("MD5 칼럼이 데이터프레임에 없거나 vir_result 테이블을 찾을 수 없습니다.")

        except Exception as e:
            QMessageBox.critical(self, "오류", f"훈련 중 오류가 발생했습니다: {e}")
            if self.status_virus_total:
                self.status_virus_total.setVisible(False)

    def display_training_results(self, results):
        if not self.train_result:
            print("train_result 테이블을 찾을 수 없습니다.")
            return

        self.train_result.setColumnCount(4)
        self.train_result.setHorizontalHeaderLabels(['모델', '정확도', '악성 개수', '양성 개수'])
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

            self.train_result.setItem(len(results), 0, QtWidgets.QTableWidgetItem("선택된 모델"))
            self.train_result.setItem(len(results), 1, QtWidgets.QTableWidgetItem(selected_model))
            self.train_result.setItem(len(results), 2, QtWidgets.QTableWidgetItem(str(max_malicious_count)))
            if benign_counts:
                max_benign_count = max(benign_counts.values())
                self.train_result.setItem(len(results), 3, QtWidgets.QTableWidgetItem(str(max_benign_count)))

    def display_confusion_matrices(self, results, Y_true):
        if not self.confusion_matrix_result:
            print("confusion_matrix_result 테이블을 찾을 수 없습니다.")
            return

        self.confusion_matrix_result.clear()
        self.confusion_matrix_result.setRowCount(len(results) * 2)
        self.confusion_matrix_result.setColumnCount(3)
        self.confusion_matrix_result.setHorizontalHeaderLabels(['모델', '예측: 아니오', '예측: 예'])

        row_idx = 0
        for model_name, (accuracy, predictions) in results.items():
            cm = confusion_matrix(Y_true, predictions)
            if cm.shape == (2, 2):
                self.confusion_matrix_result.setItem(row_idx, 0, QtWidgets.QTableWidgetItem(f"{model_name} (실제: 아니오)"))
                self.confusion_matrix_result.setItem(row_idx, 1, QtWidgets.QTableWidgetItem(str(cm[0, 0])))
                self.confusion_matrix_result.setItem(row_idx, 2, QtWidgets.QTableWidgetItem(str(cm[0, 1])))

                row_idx += 1
                self.confusion_matrix_result.setItem(row_idx, 0, QtWidgets.QTableWidgetItem(f"{model_name} (실제: 예)"))
                self.confusion_matrix_result.setItem(row_idx, 1, QtWidgets.QTableWidgetItem(str(cm[1, 0])))
                self.confusion_matrix_result.setItem(row_idx, 2, QtWidgets.QTableWidgetItem(str(cm[1, 1])))
                row_idx += 1

    def update_vir_result(self, md5_hash, result):
        if not self.vir_result:
            print("vir_result 테이블을 찾을 수 없습니다.")
            return

        try:
            if "error" in result:
                file_name = "오류"
                file_type = "오류"
                last_analysis_date = "오류"
                analysis_summary = "오류"
                file_url = "오류"
            else:
                result_data = result.get("data", {}).get("attributes", {})
                names = result_data.get("names", [])
                file_name = names[0] if names else "알 수 없음"

                file_type = result_data.get("type_description", "알 수 없음")
                last_analysis_date = result_data.get("last_analysis_date", "N/A")
                analysis_stats = result_data.get("last_analysis_stats", {})
                malicious_count = analysis_stats.get("malicious", 0)
                harmless_count = analysis_stats.get("harmless", 0)
                analysis_summary = f"악성: {malicious_count}, 무해: {harmless_count}"

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
            print(f"{md5_hash}의 결과를 파싱하는 중 오류 발생: {e}")
            current_row = self.vir_result.rowCount()
            self.vir_result.insertRow(current_row)
            self.vir_result.setItem(current_row, 0, QtWidgets.QTableWidgetItem(md5_hash))
            self.vir_result.setItem(current_row, 1, QtWidgets.QTableWidgetItem("결과 파싱 오류"))

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
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    create_file_selector()
