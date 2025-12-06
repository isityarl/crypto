import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from typing import List

from src.crypto.file_crypto import encrypt_path, decrypt_path, encrypt_and_sign_path, verify_and_decrypt_path

class SecureFileApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Yarl Lock")
        self.geometry("450x600")
        self.resizable(False, False)

        self.configure(bg="#1e1e1e")
        self.image = tk.PhotoImage(file="src/res/audi.png")
        self.keys_dir = "tests/ax/keys"

        self.selected_inputs: list[str] = []
        self.input_browse_btn = None
        self.input_clear_btn = None
        self._build_widgets()
        

    def _build_widgets(self):
        win_w, win_h = 450, 500
        img_w = self.image.width()
        img_h = self.image.height()
        w = (win_w - img_w) // 2
        h = (win_h - img_h) // 2

        self.bg_label = tk.Label(self, image=self.image)
        self.bg_label.place(x=w, y=h)


        self.input_entry = tk.Entry(self, width=35)
        self.input_entry.place(x=35, y=100)
        self.input_entry.insert(0, "Please select folder")
        self.input_entry.config(state="readonly")

        self.input_browse_btn = tk.Button(self, text='Browse', command=self.browse_input)
        self.input_browse_btn.place(x=350, y=95)

        self.input_clear_btn = tk.Button(self, text='Clear', command=self.clear_input)

        self.output_entry = tk.Entry(self, width=35)
        self.output_entry.place(x=35, y=140)
        self.output_entry.insert(0, "Output path")
        self.output_entry.config(state="readonly")
        tk.Button(self, text='Browse', command=self.browse_output).place(x=350, y=135)

        self.password_entry = tk.Entry(self, width=35)
        self.password_entry.place(x=35, y=190)
        self.password_entry.insert(0, "Password")
        self.password_entry.bind("<FocusIn>", self._on_password_focus_in)
        self.password_entry.config(bg="#2b2b2b", fg="#777777")

        self.confirm_entry = tk.Entry(self, width=35)
        self.confirm_entry.place(x=35, y=230)
        self.confirm_entry.insert(0, "Confirm password")
        self.confirm_entry.bind("<FocusIn>", self._on_confirm_focus_in)
        self.confirm_entry.config(bg="#2b2b2b", fg="#777777")


        tk.Button(self, text="Encrypt", command=self.run_encrypt, width=10).place(x=90, y=280)
        tk.Button(self, text="Decrypt", command=self.run_decrypt, width=10).place(x=230, y=280)

        self.status_label = tk.Label(self, text="", bg="#1e1e1e", fg="white")
        self.status_label.place(x=40, y=520)


    def browse_input(self):
        folder = filedialog.askdirectory()
        if not folder:
            return

        self.selected_inputs = [folder]

        self.input_entry.config(state="normal")
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, "1 folder selected")
        self.input_entry.config(state="readonly")

        self.input_browse_btn.place_forget()
        self.input_clear_btn.place(x=420, y=95)

    def clear_input(self):
        self.selected_inputs = []
        self.input_entry.config(state="normal")
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, "Please select folder")
        self.input_entry.config(state="readonly")

        self.input_clear_btn.place_forget()
        self.input_browse_btn.place(x=420, y=95)


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
        inputs = self.selected_inputs
        output_path = self.output_entry.get().strip()
        password = self.password_entry.get()

        if not inputs or not output_path or not password:
            messagebox.showerror("Error", "Didnt fill in, huh?")
            return

        try:
            for input_path in inputs:
                if operation == "encrypt":
                    encrypt_and_sign_path(input_path, output_path, password, self.keys_dir)
                else:
                    verify_and_decrypt_path(input_path, output_path, password, self.keys_dir)

            if operation == "encrypt":
                self.status_label.config(text="Encryption successful")
            else:
                self.status_label.config(text="Verification successful")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_label.config(text=f"{operation.capitalize()} failed")

    def _on_password_focus_in(self, event):
        if self.password_entry.get() == "Password":
            self.password_entry.delete(0, tk.END)
            self.password_entry.config(show="*")
            
    def _on_password_focus_in(self, event):
        if self.password_entry.get() == "Password":
            self.password_entry.delete(0, tk.END)
            self.password_entry.config(show="*")

    def _on_confirm_focus_in(self, event):
        if self.confirm_entry.get() == "Confirm password":
            self.confirm_entry.delete(0, tk.END)
            self.confirm_entry.config(show="*")
