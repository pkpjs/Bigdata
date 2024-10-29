from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow
import numpy as np
import plot_results  # plot_results.py 파일을 import


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('test.ui', self)

        # 그래프 버튼 클릭 시 그래프 표시
        self.show_graph_button.clicked.connect(self.show_graph)

    def show_graph(self):
        # 예제 데이터
        x = np.linspace(0, 10, 100)
        y = np.sin(x)

        # plot_results의 plot_graph 함수를 호출하여 graphicsView에 그래프 표시
        plot_results.plot_graph(self.graphicsView, x, y)


# 실행 부분
if __name__ == "__main__":
    app = QApplication([])
    window = MyApp()
    window.show()
    app.exec_()
