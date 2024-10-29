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


        self.load_data_into_table(pd.DataFrame(X_new).describe(()))

        # 모델 학습 및 평가
        classifier = Classifiers(X_new, Y)
        results = {
            'svm': classifier.do_svm(),
            'randomforest': classifier.do_randomforest(),
            'naivebayes': classifier.do_naivebayes(),
            'dnn': classifier.do_dnn(epochs=10)
        }

        # 결과를 저장할 리스트 생성
        result_data = []
        malicious_counts = {}

        for model, (accuracy, predictions) in results.items():
            count_malicious = (predictions == 1).sum()
            count_benign = (predictions == 0).sum()
            malicious_counts[model] = count_malicious

            # 결과 데이터 저장
            result_dict = {
                '모델': model,
                '정확도': f"{accuracy:.4f}",
                '악성 파일 수': count_malicious,
                '정상 파일 수': count_benign
            }
            result_data.append(result_dict)

        # 최적 모델 찾기
        max_malicious_count = max(malicious_counts.values())
        best_models = [model for model, count in malicious_counts.items()
                       if count == max_malicious_count]
        selected_model = best_models[0]

        # 결과 데이터프레임 생성
        results_df = pd.DataFrame(result_data)

        # 최적 모델 정보를 데이터프레임에 추가
        best_model_info = pd.DataFrame([{
            '모델': f'최적 모델: {selected_model}',
            '정확도': '',
            '악성 파일 수': max_malicious_count,
            '정상 파일 수': ''
        }])

        results_df = pd.concat([results_df, best_model_info], ignore_index=True)

        # 테이블에 결과 표시
        self.load_data_into_table(results_df)

        # MD5 해시 확인 및 VirusTotal API 작업
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
        """데이터프레임을 QTableWidget에 로드하는 메소드"""
        # 테이블 크기 설정
        self.data_preprocessor_output.setRowCount(len(df))
        self.data_preprocessor_output.setColumnCount(len(df.columns))

        # 열 이름 설정
        self.data_preprocessor_output.setHorizontalHeaderLabels(df.columns.astype(str).tolist())

        # 데이터 입력
        for i in range(len(df)):
            for j in range(len(df.columns)):
                value = df.iloc[i, j]
                # 숫자인 경우 소수점 4자리까지 표시
                if isinstance(value, (float, int)):
                    item = QtWidgets.QTableWidgetItem(f"{value:.4f}" if isinstance(value, float) else str(value))
                else:
                    item = QtWidgets.QTableWidgetItem(str(value))
                self.data_preprocessor_output.setItem(i, j, item)

        # 열 너비 자동 조정
        self.data_preprocessor_output.resizeColumnsToContents()

        # 테이블 스타일 설정
        self.data_preprocessor_output.setStyleSheet()


def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()


# 실행 부분
if __name__ == "__main__":
    create_file_selector()