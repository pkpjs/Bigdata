from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
import threading
import random
import time
import pandas as pd
from data_loader import DataLoader
from data_preprocessor import DataPreprocessor, FeatureSelector
from classifiers import Classifiers
from VirusTotal_API import VirusTotalAPI
from hash_checker import check_hashes
from config import API_KEY
from plot_results import plot_results

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)  # UI 파일 로드

        # train_button 클릭 시 handle_train 호출
        self.train_button.clicked.connect(self.handle_train)

        # data_select 버튼 클릭 시 파일 선택 다이얼로그 연결
        self.data_select.clicked.connect(self.select_malware_file)

        # 기본 정상 파일 설정
        self.normal_file = 'normal_pe (1).csv'
        self.nomal_file.setText(self.normal_file)  # 정상 파일 라벨에 기본값 설정

    def select_malware_file(self):
        # 악성 파일 선택 다이얼로그
        malware_file, _ = QFileDialog.getOpenFileName(self, "악성 데이터 파일을 선택하세요", "", "CSV Files (*.csv)")
        if malware_file:
            self.malware_file.setText(malware_file)  # 선택한 악성 파일 경로를 라벨에 표시

    def handle_train(self):
        # 처리 시작 버튼 클릭 시 실행될 코드
        api_key = API_KEY

        # 파일 선택
        normal_file = self.normal_file
        malware_file = self.malware_file.text()
        ngram_file = 'ngram (1).csv'

        data_loader = DataLoader(normal_file, malware_file, ngram_file)
        pe_all = data_loader.load_data(load_malware=malware_file is not None)

        if pe_all.empty:
            print("데이터가 비어 있습니다. 파일 경로를 확인하세요.")
            return

        pe_all = pe_all.loc[:, ~pe_all.columns.duplicated()]
        pe_all.reset_index(drop=True, inplace=True)

        preprocessor = DataPreprocessor(pe_all)
        preprocessor.filter_na()
        preprocessor.drop_columns(['filename', 'MD5', 'packer_type'])
        X, Y = preprocessor.get_features_and_labels()

        X = preprocessor.remove_constant_features(X)

        feature_selector = FeatureSelector(X, Y)
        X_new = feature_selector.select_features()

        # 선택된 특성 요약 데이터 출력
        self.load_data_into_table(pd.DataFrame(X_new).describe())  # QTableWidget에 데이터 출력

        classifier = Classifiers(X_new, Y)
        results = {
            'svm': classifier.do_svm(),
            'randomforest': classifier.do_randomforest(),
            'naivebayes': classifier.do_naivebayes(),
            'dnn': classifier.do_dnn(epochs=10)
        }

        print("모델 평가 결과:")
        malicious_counts = {}
        for model, (accuracy, predictions) in results.items():
            print(f"{model} 정확도: {accuracy:.4f}")

            count_malicious = (predictions == 1).sum()
            count_benign = (predictions == 0).sum()

            print(f"악성 파일 개수: {count_malicious}, 정상 파일 개수: {count_benign}\n")

            malicious_counts[model] = count_malicious

        max_malicious_count = max(malicious_counts.values())
        best_models = [model for model, count in malicious_counts.items() if count == max_malicious_count]

        selected_model = best_models[0]
        print(f"선택된 모델: {selected_model} (악성 파일 개수: {max_malicious_count})")

        pe_all['class'] = Y
        if 'MD5' in pe_all.columns:
            malicious_md5 = pe_all.loc[pe_all['class'] == 1, 'MD5']
            print("악성 파일의 MD5 해시 값:")
            md5_list = malicious_md5.tolist()

            if len(md5_list) > 10:
                selected_md5_list = random.sample(md5_list, 10)
            else:
                selected_md5_list = md5_list

            vt_api = VirusTotalAPI(api_key)

            # VirusTotal API 쓰레드 시작
            thread = threading.Thread(target=check_hashes, args=(vt_api, selected_md5_list))
            thread.start()

            # MD5 해시 확인하는 동안 대기
            for md5_hash in selected_md5_list:
                time.sleep(0.25)

            # 쓰레드가 끝날 때까지 대기
            thread.join()

            print("바이러스 토탈 API 결과 확인이 완료되었습니다.")
        else:
            print("MD5 칼럼이 데이터프레임에 없습니다.")

        # 모든 작업이 완료된 후 그래프 출력
        plot_results(results, malicious_counts)

    def load_data_into_table(self, df):
        # 인덱스 값도 포함하도록 열 수를 한 칸 더 추가
        self.data_preprocessor_output.setRowCount(len(df))  # 행 수 설정
        self.data_preprocessor_output.setColumnCount(len(df.columns) + 1)  # 인덱스를 위한 열 추가

        # 열 이름 설정 (첫 번째는 빈 값으로 설정하여 인덱스를 위한 자리)
        self.data_preprocessor_output.setHorizontalHeaderLabels([''] + df.columns.astype(str).tolist())

        # 인덱스와 데이터를 QTableWidget에 로드
        for row in range(len(df)):
            # 인덱스 값 삽입
            index_item = QtWidgets.QTableWidgetItem(str(df.index[row]))
            self.data_preprocessor_output.setItem(row, 0, index_item)  # 첫 번째 열에 인덱스 값 삽입

            # 나머지 데이터 삽입
            for col in range(len(df.columns)):
                item = QtWidgets.QTableWidgetItem(str(df.iat[row, col]))
                self.data_preprocessor_output.setItem(row, col + 1, item)  # 두 번째 열부터 데이터 삽입


def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()

# 실행 부분
if __name__ == "__main__":
    create_file_selector()
