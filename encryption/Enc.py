import os
import keyring
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import hashlib
import string
import webbrowser
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

history = []

# AES Encryption & Decryption
def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))

def decrypt_aes(data, key):
    iv, data = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

# Password Storage using keyring
def store_password(file_path, password):
    keyring.set_password("SecureFileEncryption", file_path, password)

def verify_password(file_path, password):
    stored_password = keyring.get_password("SecureFileEncryption", file_path)
    return stored_password is not None and stored_password == password

# File Encryption & Decryption
def encrypt_file(file_path, password):
    key = hash_password(password)
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        ciphertext = encrypt_aes(plaintext, key)
        new_file_path = file_path + ".enc"
        with open(new_file_path, 'wb') as f:
            f.write(ciphertext)
        store_password(new_file_path, password)
        history.append(new_file_path)
        update_status("File encrypted successfully!", "success")
    except Exception as e:
        update_status(f"Error: {str(e)}", "danger")

def decrypt_file(file_path, password):
    if not verify_password(file_path, password):
        update_status("Incorrect password!", "danger")
        return
    key = hash_password(password)
    try:
        with open(file_path, 'rb') as f:
            ciphertext = f.read()
        plaintext = decrypt_aes(ciphertext, key)
        base = file_path[:-4]  
        root_name, ext = os.path.splitext(base)
        base = file_path[:-4]  
        new_file_path = base  # restore original file name with extension

        with open(new_file_path, 'wb') as f:
            f.write(plaintext)
        history.append(new_file_path)
        update_status("File decrypted successfully!", "success")
    except Exception as e:
        update_status(f"Error: {str(e)}", "danger")

# Password Validation
def validate_password(password: str) -> bool:
    return (
        len(password) >= 8
        and any(c.isupper() for c in password)
        and any(c in string.punctuation for c in password)
    )

def password_entry_window(action_callback, confirm=False):
    password_window = ttk.Toplevel(root)
    password_window.title("Enter Password")
    password_window.geometry("400x300")
    password_window.configure(bg="#2C3E50")

    password_var = ttk.StringVar()
    confirm_password_var = ttk.StringVar()
    show_password_var = ttk.BooleanVar()

    ttk.Label(password_window, text="Enter Password:", foreground="white", background="#2C3E50").pack(pady=5)
    password_entry = ttk.Entry(password_window, textvariable=password_var, show='*')
    password_entry.pack(pady=5)

    if confirm:
        ttk.Label(password_window, text="Confirm Password:", foreground="white", background="#2C3E50").pack(pady=5)
        confirm_password_entry = ttk.Entry(password_window, textvariable=confirm_password_var, show='*')
        confirm_password_entry.pack(pady=5)

    def toggle_password():
        show = '' if show_password_var.get() else '*'
        password_entry.config(show=show)
        if confirm:
            confirm_password_entry.config(show=show)

    ttk.Checkbutton(password_window, text="Show Password", variable=show_password_var, command=toggle_password).pack()

    def submit_password():
        password = password_var.get()
        if confirm:
            confirm_password = confirm_password_var.get()
            if password != confirm_password:
                update_status("Passwords do not match!", "danger")
                return
            if not validate_password(password):
                update_status("Password must be 8+ characters, include a symbol & uppercase letter!", "danger")
                return
        action_callback(password)
        password_window.destroy()

    ttk.Button(password_window, text="Submit", command=submit_password).pack(pady=10)

def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password_entry_window(lambda password: encrypt_file(file_path, password), confirm=True)

def select_file_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password_entry_window(lambda password: decrypt_file(file_path, password), confirm=False)

def update_status(message, style):
    status_label.config(text=message, bootstyle=style)

def view_history():
    history_window = ttk.Toplevel(root)
    history_window.title("Encryption/Decryption History")
    history_window.geometry("400x300")
    history_window.configure(bg="#2C3E50")
    ttk.Label(history_window, text="History:", foreground="white", background="#2C3E50").pack(pady=5)
    for file in history:
        link = ttk.Label(history_window, text=file, cursor="hand2", foreground="lightblue", background="#2C3E50")
        link.pack(pady=2)
        link.bind("<Button-1>", lambda e, path=file: webbrowser.open(f"file://{path}"))

# GUI Setup
root = ttk.Window(themename="darkly")
root.title("Secure File Encryption App")
root.geometry("1000x700")
root.configure(bg="#34495E")
root.resizable(True, True)

title_label = ttk.Label(root, text="Secure File Encryption", font=("Helvetica", 24, "bold"), foreground="white", background="#34495E")
title_label.pack(pady=20)

ttk.Button(root, text="Select File to Encrypt", command=select_file_encrypt, bootstyle="primary").pack(pady=5)
ttk.Button(root, text="Select File to Decrypt", command=select_file_decrypt, bootstyle="primary").pack(pady=5)
ttk.Button(root, text="View History", command=view_history, bootstyle="secondary").pack(pady=5)

status_label = ttk.Label(root, text="", font=("Helvetica", 12), foreground="white", background="#34495E")
status_label.pack(pady=5)

ttk.Label(root, text="Made by Yugam", font=("Gothic", 10), foreground="lightgray", background="#34495E").pack(side=BOTTOM, pady=10)

root.mainloop()
