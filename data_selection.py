import tkinter as tk
from tkinter import filedialog

def load_file(title):
    # 파일 대화 상자를 열어 사용자가 파일을 선택할 수 있게 함
    file_path = filedialog.askopenfilename(title=title, filetypes=[("CSV files", "*.csv")])
    return file_path

def create_file_selector():
    # Tkinter GUI 설정
    root = tk.Tk()
    root.title("데이터 파일 선택기")

    # 정상 데이터 파일 입력 필드 및 변수
    normal_file_entry = tk.Entry(root, width=50)
    normal_file_entry.pack(pady=5)

    # 악성 데이터 파일 입력 필드 및 변수
    malware_file_entry = tk.Entry(root, width=50)
    malware_file_entry.pack(pady=5)

    # 기본 악성 데이터 파일 이름 설정
    default_malware_file = 'malware_pe (1).csv'

    # 정상 데이터 추가 여부 선택
    def on_normal_data_choice(choice):
        if choice == "yes":
            normal_file = load_file("정상 데이터 파일을 선택하세요")
            if normal_file:  # 파일이 선택된 경우에만 입력
                normal_file_entry.insert(0, normal_file)
            show_malware_file_selector()
        else:
            normal_file_entry.insert(0, 'normal_pe (1).csv')  # 기본 정상 데이터 파일
            show_malware_file_selector()

    def show_malware_file_selector():
        # 악성 데이터 파일 선택 여부 질문
        malware_question_label = tk.Label(root, text="악성 데이터 파일을 선택하시겠습니까? (yes/no):")
        malware_question_label.pack(pady=10)

        yes_button = tk.Button(root, text="Yes", command=select_malware_file)
        yes_button.pack(pady=5)

        no_button = tk.Button(root, text="No", command=use_default_malware_file)
        no_button.pack(pady=5)

    def select_malware_file():
        # 악성 데이터 파일 선택 후 경로를 입력 필드에 표시
        malware_file = load_file("악성 데이터 파일을 선택하세요")
        if malware_file:  # 파일이 선택된 경우에만 입력
            malware_file_entry.delete(0, tk.END)
            malware_file_entry.insert(0, malware_file)  # 선택한 경로 입력
        finalize_selection()

    def use_default_malware_file():
        # 기본 악성 데이터 파일 사용
        malware_file_entry.delete(0, tk.END)
        malware_file_entry.insert(0, default_malware_file)  # 기본값 입력
        finalize_selection()

    def finalize_selection():
        # 최종적으로 선택된 파일 경로 반환
        start_button.config(state=tk.NORMAL)  # 시작 버튼 활성화

    # 시작 버튼 (처리 시작)
    start_button = tk.Button(root, text="처리 시작", command=root.quit, state=tk.DISABLED)  # 비활성화 상태로 시작
    start_button.pack(pady=20)

    # 정상 데이터 추가 여부 질문
    question_label = tk.Label(root, text="정상 데이터 파일을 추가하시겠습니까? (yes/no):")
    question_label.pack(pady=10)

    yes_button = tk.Button(root, text="Yes", command=lambda: on_normal_data_choice("yes"))
    yes_button.pack(pady=5)

    no_button = tk.Button(root, text="No", command=lambda: on_normal_data_choice("no"))
    no_button.pack(pady=5)

    root.mainloop()

    return normal_file_entry.get(), malware_file_entry.get()  # 입력된 파일 경로 반환
