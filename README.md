# Bigdata

# 프로젝트 이름
이 프로젝트는 __악성코드 탐지__를 위한 모델을 만들기 위한 코드입니다.

## 기능
- 악성코드와 정상코드 데이터를 분류
- 특정 해시 값을 VirusTotal API로 확인
- SVM, 랜덤 포레스트, 나이브 베이즈, DNN 모델 사용

## 주의 사항
- 무료 API 사용으로 인해 1분에 4건 하루에 500개 밖에 조회 안됨
- config.py 파일에 자신의 API 입력후 실행

## 설치
다음 명령어로 패키지를 설치하세요:
```bash
pip install -r requirements.txt
