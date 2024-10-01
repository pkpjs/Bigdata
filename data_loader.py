import pandas as pd


class DataLoader:
    def __init__(self, normal_file, malware_file=None, ngram_file=None):
        self.normal_file = normal_file
        self.malware_file = malware_file
        self.ngram_file = ngram_file

    def load_data(self, load_malware=True):
        pe_nor = pd.read_csv(self.normal_file)  # 정상 데이터 로드
        pe_all = pe_nor  # 기본적으로 정상 데이터만

        if load_malware and self.malware_file:  # 악성 데이터 로드 여부 확인
            pe_mal = pd.read_csv(self.malware_file)  # 악성 데이터 로드
            pe_all = pd.concat([pe_nor, pe_mal])  # 두 데이터를 합침

        return pe_all

    def load_ngram(self):
        return pd.read_csv(self.ngram_file) if self.ngram_file else None
