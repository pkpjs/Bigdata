from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
import random
import pandas as pd
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from VirusTotal_API import VirusTotalAPI
from config import API_KEY
import time


class VirusTotalThread(QThread):
    hash_result = pyqtSignal(str, dict)
    progress_update = pyqtSignal(str)
    finished = pyqtSignal(str)

    def __init__(self, api_key, md5_list):
        super().__init__()
        self.api_key = api_key
        self.md5_list = md5_list

    def run(self):
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


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)

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


def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()


if __name__ == "__main__":
    create_file_selector()