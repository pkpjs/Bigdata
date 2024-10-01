import pandas as pd

class DataLoader:
    def __init__(self, normal_file, malware_file, ngram_file):
        self.normal_file = normal_file
        self.malware_file = malware_file
        self.ngram_file = ngram_file

    def load_data(self):
        pe_nor = pd.read_csv(self.normal_file)
        pe_mal = pd.read_csv(self.malware_file)
        pe_all = pd.concat([pe_nor, pe_mal])
        return pe_all

    def load_ngram(self):
        return pd.read_csv(self.ngram_file)
