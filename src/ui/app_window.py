import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List

class SecureFileApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Encryption")
        self.selected_files: List[str] = []
        self._build_widgets()

    def _build_widgets(self): #layout UI elements
        pass

    def select_files(self): #select which files to encrypt
        pass

    def run_encrypt(self): #call ecnryption
        pass

    def run_decrypt(self): #call decryption
        pass
