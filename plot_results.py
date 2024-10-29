from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib.pyplot as plt


def plot_graph(view, x, y):
    """
    QGraphicsView에 실선 그래프를 표시하는 함수입니다.

    :param view: QGraphicsView 위젯
    :param x: x축 데이터 리스트 또는 배열
    :param y: y축 데이터 리스트 또는 배열
    """
    # matplotlib로 그래프 그리기
    fig, ax = plt.subplots()
    ax.plot(x, y, linestyle='-', color='blue')  # 실선 그래프

    # Figure를 QImage로 변환하여 QGraphicsView에 표시
    canvas = FigureCanvas(fig)
    canvas.draw()

    # canvas 이미지를 RGBA 바이트 배열로 변환
    width, height = canvas.get_width_height()
    image = QImage(canvas.buffer_rgba(), width, height, QImage.Format_RGBA8888)

    # QPixmap으로 변환 후 QGraphicsScene에 추가
    pixmap = QPixmap.fromImage(image)
    scene = QGraphicsScene()
    scene.addPixmap(pixmap)
    view.setScene(scene)

    # 메모리 해제
    plt.close(fig)
