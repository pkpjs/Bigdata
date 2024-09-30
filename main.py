import pandas as pd
from data_preprocessing import load_data, preprocess_data, hot_encoding
from classifiers import Classifiers

# 데이터 로드
pe_all, gram_all = load_data('normal_pe (1).csv', 'malware_pe (1).csv', 'ngram (1).csv')

# 데이터 전처리
X, Y, pe_all_tmp = preprocess_data(pe_all)

# 모델 학습 및 결과 저장
md_pe = Classifiers(X, Y)
df = pd.DataFrame(columns=["svm", "randomforest", "naivebayes", "dnn"])
df.loc['pe'] = md_pe.do_all()

# 원-핫 인코딩
pe_all = pe_all_tmp.copy()
pe_all, classes_ = hot_encoding(pe_all)

# 데이터셋 저장
pe_all.to_csv('pe_packer.csv', index=False)

# 추가 데이터 전처리 및 모델 학습
Y = pe_all['class']
X = pe_all.drop('class', axis=1)

md_pe_packer = Classifiers(X, Y)
df.loc['pe_packer'] = md_pe_packer.do_all()

# n-gram 데이터 전처리
gram_all = gram_all.drop(['filename', 'MD5'], axis=1)
Y = gram_all['class']
X = gram_all.drop('class', axis=1)

md_gram = Classifiers(X, Y)
df.loc['ngram'] = md_gram.do_all()
df.loc['image'] = [0, 0, 0, 0]

# 최종 결과 출력
print(df)
avg_pe = df.loc['pe'].mean(axis=0)
avg_pe_packer = df.loc['pe_packer'].mean(axis=0)
avg_gram = df.loc['ngram'].mean(axis=0)
df.loc['avg'] = [avg_pe, avg_pe_packer, avg_gram, 0]
print(df)
