import tkinter as tk
from tkinter import filedialog

def load_file(title):
    file_path = filedialog.askopenfilename(title=title, filetypes=[("CSV files", "*.csv")])
    return file_path

def create_file_selector():
    root = tk.Tk()
    root.title("데이터 파일 선택기")

    # 정상 데이터 파일 입력 필드 및 변수
    normal_file_entry = tk.Entry(root, width=50)
    normal_file_entry.pack(pady=5)
    normal_file_entry.insert(0, 'normal_pe (1).csv')  # 기본 정상 데이터 파일

    # 악성 데이터 파일 입력 필드 및 변수
    malware_file_entry = tk.Entry(root, width=50)
    malware_file_entry.pack(pady=5)

    default_malware_file = 'malware_pe (1).csv'

    def select_malware_file():
        malware_file = load_file("악성 데이터 파일을 선택하세요")
        if malware_file:
            malware_file_entry.delete(0, tk.END)
            malware_file_entry.insert(0, malware_file)  # 선택한 경로 입력
        finalize_selection()

    def use_default_malware_file():
        malware_file_entry.delete(0, tk.END)
        malware_file_entry.insert(0, default_malware_file)  # 기본값 입력
        finalize_selection()

    def finalize_selection():
        start_button.config(state=tk.NORMAL)  # 시작 버튼 활성화

    # 시작 버튼 (처리 시작)
    start_button = tk.Button(root, text="처리 시작", command=root.quit, state=tk.DISABLED)  # 비활성화 상태로 시작
    start_button.pack(pady=20)

    # 악성 데이터 파일 선택 여부 질문
    malware_question_label = tk.Label(root, text="악성 데이터 파일을 선택하시겠습니까? (yes/no):")
    malware_question_label.pack(pady=10)

    yes_button = tk.Button(root, text="Yes", command=select_malware_file)
    yes_button.pack(pady=5)

    no_button = tk.Button(root, text="No", command=use_default_malware_file)
    no_button.pack(pady=5)

    root.mainloop()

    return normal_file_entry.get(), malware_file_entry.get()  # 입력된 파일 경로 반환
