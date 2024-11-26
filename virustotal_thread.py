# virustotal_thread.py
from PyQt5.QtCore import QThread, pyqtSignal
from virustotal_api import VirusTotalAPI

class VirusTotalThread(QThread):
    vt_complete = pyqtSignal(dict)

    def __init__(self, sha256_list, api_key):
        super().__init__()
        self.sha256_list = sha256_list
        self.api_key = api_key

    def run(self):
        vt_api = VirusTotalAPI(self.api_key)
        vt_results = vt_api.check_hashes_with_virustotal(self.sha256_list)
        self.vt_complete.emit(vt_results)
