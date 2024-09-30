import pandas as pd
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.decomposition import PCA
from sklearn.preprocessing import OneHotEncoder, LabelEncoder


def load_data(normal_file, malware_file, ngram_file):
    pe_nor = pd.read_csv(normal_file)
    pe_mal = pd.read_csv(malware_file)
    pe_all = pd.concat([pe_nor, pe_mal])

    gram_all = pd.read_csv(ngram_file)
    return pe_all, gram_all


def preprocess_data(pe_all):
    print("[*] Before Filtering NA values: ", pe_all.shape)
    NA_values = pe_all.isnull().values.sum()
    print("[*] Missing Values: ", NA_values)
    pe_all = pe_all.dropna()
    print("[*] After Filtering NA values: ", pe_all.shape)

    pe_all_tmp = pe_all.copy()
    pe_all = pe_all.drop(['filename', 'MD5', 'packer_type'], axis=1)
    print(pe_all.shape)

    Y = pe_all['class']
    X = pe_all.drop('class', axis=1)

    # 특성 선택 및 PCA
    X = SelectKBest(f_classif, k=50).fit_transform(X, Y)
    pca = PCA(n_components=50)
    X = pca.fit_transform(X)

    return X, Y, pe_all_tmp


def hot_encoding(df):
    enc = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    lab = LabelEncoder()
    dat = df['packer_type']
    lab.fit(dat)
    lab_dat = lab.transform(dat)
    df = df.drop('packer_type', axis=1)
    lab_dat = lab_dat.reshape(len(lab_dat), 1)
    enc_dat = enc.fit_transform(lab_dat)
    enc_dat = pd.DataFrame(enc_dat, columns=lab.classes_)
    df = df.reset_index(drop=True)
    enc_dat = enc_dat.reset_index(drop=True)
    df = pd.concat([df, enc_dat], axis=1)
    return df, lab.classes_
