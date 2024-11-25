import pandas as pd


class DataLoader:
    def __init__(self, malware_file):
        self.malware_file = malware_file


    def load_data(self):
        if not self.malware_file:
            raise ValueError("악성 파일 경로가 제공되지 않았습니다.")

        pe_all = pd.read_csv(self.malware_file)  # 악성 데이터 로드
        return pe_all