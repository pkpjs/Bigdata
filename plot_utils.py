from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib.pyplot as plt
from matplotlib import font_manager, rc

# 한글 폰트 설정
font_path = "C:/Windows/Fonts/malgun.ttf"  # Windows: 맑은 고딕
font = font_manager.FontProperties(fname=font_path).get_name()
rc('font', family=font)
plt.rcParams['axes.unicode_minus'] = False  # 음수 기호가 깨지지 않도록 설정

def plot_graph(view, x, y, title='Graph', xlabel='X-axis', ylabel='Y-axis', linestyle='-', marker='o', color='blue'):
    """
    QGraphicsView에 matplotlib 그래프를 실선으로 그리는 함수.

    Parameters:
    - view: QGraphicsView 객체
    - x: x축 데이터 (리스트 또는 배열)
    - y: y축 데이터 (리스트 또는 배열)
    - title: 그래프 제목
    - xlabel: x축 레이블
    - ylabel: y축 레이블
    - linestyle: 선 스타일 (기본값: 실선 '-')
    - marker: 마커 스타일 (기본값: 'o')
    - color: 선 색상 (기본값: 'blue')
    """
    # matplotlib로 그래프 그리기
    fig, ax = plt.subplots()
    ax.plot(x, y, linestyle=linestyle, marker=marker, color=color)  # 실선 그래프

    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True)

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
