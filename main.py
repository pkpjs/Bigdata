from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
import random
import pandas as pd
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from VirusTotal_API import VirusTotalAPI
from hash_checker import check_hashes
from config import API_KEY
from plot_results import plot_results


def check_hashes(vt_api, md5_list, result_callback):
    """MD5 해시를 사용하여 바이러스 토탈에서 검사하고 결과를 콜백 함수로 전달합니다."""
    vt_results = vt_api.check_hashes_with_virustotal(md5_list)
    for md5_hash, result in vt_results.items():
        result_callback(md5_hash, result)


class VirusTotalThread(QThread):
    hash_result = pyqtSignal(str, dict)
    finished = pyqtSignal(str)

    def __init__(self, api_key, md5_list):
        super().__init__()
        self.api_key = api_key
        self.md5_list = md5_list

    def run(self):
        vt_api = VirusTotalAPI(self.api_key)
        check_hashes(vt_api, self.md5_list, self.hash_result.emit)
        self.finished.emit("바이러스 토탈 API 검사 완료")


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)

        self.train_button.clicked.connect(self.handle_train)
        self.data_select.clicked.connect(self.select_malware_file)
        self.normal_file = 'normal_pe (1).csv'
        self.nomal_file.setText(self.normal_file)

        self.vir_result.setColumnCount(6)
        self.vir_result.setHorizontalHeaderLabels(['MD5', 'File Name', 'Type', 'Analysis Date', 'Summary', 'URL'])
        self.train_result.setColumnCount(3)
        self.train_result.setHorizontalHeaderLabels(['Model', 'Accuracy', 'Malicious Count'])

    def select_malware_file(self):
        malware_file, _ = QFileDialog.getOpenFileName(self, "악성 데이터 파일을 선택하세요", "", "CSV Files (*.csv)")
        if malware_file:
            self.malware_file.setText(malware_file)

    def handle_train(self):
        api_key = API_KEY
        normal_file = self.normal_file
        malware_file = self.malware_file.text()
        ngram_file = 'ngram (1).csv'

        data_loader = DataLoader(normal_file, malware_file, ngram_file)
        pe_all = data_loader.load_data(load_malware=malware_file is not None)

        preprocessor = DataPreprocessor(pe_all)
        preprocessor.filter_na()
        preprocessor.drop_columns(['filename', 'MD5', 'packer_type'])
        X, Y = preprocessor.get_features_and_labels()
        X = preprocessor.remove_constant_features(X)
        feature_selector = FeatureSelector(X, Y)
        X_new = feature_selector.select_features()

        self.load_data_into_table(pd.DataFrame(X_new).describe(), self.data_preprocessor_output)

        classifier = Classifiers(X_new, Y)
        results = {
            'svm': classifier.do_svm(),
            'randomforest': classifier.do_randomforest(),
            'naivebayes': classifier.do_naivebayes(),
            'dnn': classifier.do_dnn(epochs=10)
        }
        self.display_training_results(results)

        if 'MD5' in pe_all.columns:
            malicious_md5 = pe_all.loc[pe_all['class'] == 1, 'MD5']
            md5_list = malicious_md5.tolist()

            if len(md5_list) > 10:
                selected_md5_list = random.sample(md5_list, 10)
            else:
                selected_md5_list = md5_list

            self.vt_thread = VirusTotalThread(api_key, selected_md5_list)
            self.vt_thread.hash_result.connect(self.update_vir_result)
            self.vt_thread.finished.connect(self.on_vt_thread_finished)
            self.vt_thread.start()
        else:
            print("MD5 칼럼이 데이터프레임에 없습니다.")

    def load_data_into_table(self, df, table_widget):
        table_widget.setRowCount(len(df))
        table_widget.setColumnCount(len(df.columns) + 1)
        table_widget.setHorizontalHeaderLabels([''] + df.columns.astype(str).tolist())

        for row in range(len(df)):
            index_item = QtWidgets.QTableWidgetItem(str(df.index[row]))
            table_widget.setItem(row, 0, index_item)

            for col in range(len(df.columns)):
                item = QtWidgets.QTableWidgetItem(str(df.iat[row, col]))
                table_widget.setItem(row, col + 1, item)

    def display_training_results(self, results):
        self.train_result.setRowCount(len(results) + 1)

        malicious_counts = {}
        for row, (model, (accuracy, predictions)) in enumerate(results.items()):
            count_malicious = (predictions == 1).sum()
            malicious_counts[model] = count_malicious

            self.train_result.setItem(row, 0, QtWidgets.QTableWidgetItem(model))
            self.train_result.setItem(row, 1, QtWidgets.QTableWidgetItem(f"{accuracy:.4f}"))
            self.train_result.setItem(row, 2, QtWidgets.QTableWidgetItem(str(count_malicious)))

        max_malicious_count = max(malicious_counts.values())
        best_models = [model for model, count in malicious_counts.items() if count == max_malicious_count]
        selected_model = best_models[0]

        self.train_result.setItem(len(results), 0, QtWidgets.QTableWidgetItem("Selected Model"))
        self.train_result.setItem(len(results), 1, QtWidgets.QTableWidgetItem(selected_model))
        self.train_result.setItem(len(results), 2, QtWidgets.QTableWidgetItem(str(max_malicious_count)))

    def update_vir_result(self, md5_hash, result):
        try:
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
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText(message)
        msg_box.setWindowTitle("검사 완료")
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()


def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()


if __name__ == "__main__":
    create_file_selector()
