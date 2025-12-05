import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List

from src.crypto.file_crypto import encrypt_path, decrypt_path

class SecureFileApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Yarl Lock")
        self.geometry("550x700")
        self.resizable(False, False)

        self.configure(bg="#1e1e1e")
        self.image = tk.PhotoImage(file="src/res/audi.png")
        self._build_widgets()
        

    def _build_widgets(self):
        win_w, win_h = 550, 600
        img_w = self.image.width()
        img_h = self.image.height()
        w = (win_w - img_w) // 2
        h = (win_h - img_h) // 2

        self.bg_label = tk.Label(self, image=self.image)
        self.bg_label.place(w, h)


        tk.Label(self, text="Input:").place(40, 100)
        self.input_entry = tk.Entry(self, width=35)
        self.input_entry.place(100, 100)
        tk.Button(self, text='Browse', command=self.browse_input).place(420, 95)

        tk.Label(self, text="Output:").place(40, 140)
        self.output_entry = tk.Entry(self, width=35)
        self.output_entry.place(100, 140)
        tk.Button(self, text='Browse', command=self.browse_output).place(420, 135)

        tk.Label(self, text="Password:").place(40, 180)
        self.password_entry = tk.Entry(self, width=35, show="*")
        self.password_entry.place(120, 180)

        tk.Button(self, text="Encrypt", command=self.run_encrypt, width=10).place(160, 480)
        tk.Button(self, text="Decrypt", command=self.run_decrypt, width=10).place(300, 480)



    def browse_input(self):
        path = filedialog.askopenfilename()
        if not path:
            path = filedialog.askopenfilename()
        if path:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, path)

    def browse_output(self):
        path = filedialog.askdirectory()
        if path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, path)

    def run_encrypt(self):
        self._run_crypto("encrypt")

    def run_decrypt(self):
        self._run_crypto("decrypt")

    def _run_crypto(self, operation: str):
        input_path = self.input_entry.get().strip()
        output_path = self.output_entry.get().strip()
        password = self.password_entry.get()

        if not input_path or not output_path or not password:
            messagebox.showerror("Error", "Didnt fill in, huh?")
            return
        if operation == "encrypt":
            encrypt_path(input_path, output_path, password)
        else:
            decrypt_path(input_path, output_path, password)
        self.status_label.config(text=f"{operation.capitalize()}ion successful")