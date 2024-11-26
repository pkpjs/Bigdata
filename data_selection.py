from PyQt5 import uic
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)  # 수정된 .ui 파일 로드

        # data_select 버튼 클릭 시 파일 선택 다이얼로그 연결
        self.data_select.clicked.connect(self.select_malware_file)

    def select_malware_file(self):
        # 악성 파일 선택 다이얼로그
        malware_file, _ = QFileDialog.getOpenFileName(self, "악성 데이터 파일을 선택하세요", "", "CSV Files (*.csv)")
        if malware_file:
            self.malware_file.setText(malware_file)  # 선택한 악성 파일 경로를 라벨에 표시

def create_file_selector():
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()

# 실행 부분
if __name__ == "__main__":
    create_file_selector()
