import os
import sys
import hashlib
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet
from Cryptodome.Cipher import AES
import tkinter.simpledialog
import unittest
from PIL import Image, ImageTk

# Generate a key and encrypt the message
key = Fernet.generate_key()
cipher_suite = Fernet(key)
cipher_text = cipher_suite.encrypt(b'This is my secret message')

# Save the key to a file
with open('filekey.key', 'wb') as filekey:
    filekey.write(key)

# Save the encrypted message to a file
with open('encrypted_message.txt', 'wb') as file:
    file.write(cipher_text)

# Version control
__version__ = "1.1"

# Encryption 

class EncryptionTool:
    def __init__(self, user_file, user_key, user_salt):
        self.user_file = user_file
        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size =1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")
        self.file_extension = self.user_file.split(".")[-1]
        self.hash_type ="SHA256"
        self.encrypt_output_file = ".".join(self.user_file.split)(".")[:-1] \
                                   + "." + self.file_extension + ".seyp"
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
                                   + "__deseypted__." + self.decrypt_output_file[-1]
        self.hashed_key_salt = dict()
        self.hash_key_salt()


# Read Memory Size
    def read_in_chunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

# Encrypted and decrypted key 
    
    def encrypt(self):
        cipher_object = AES.new(
            self.hashed_key_salt["key"],
            AES.MODE_CFB,
            self.hashed_key_salt["salt"]
        )


        self.abort()
        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()
        del cipher_object
        os.remove(self.user_file)

    
    def decrypt(self):
        cipher_object = AES.new(
            self.hashed_key_salt["key"],
            AES.MODE_CFB,
             self.hashed_key_salt["salt"]
        )

        self.abort()
        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:32], "utf-8")
        del hasher

        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:16], "utf-8")
        del hasher


# GUI MENU 
        
class MainWindow:
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))
       
    def __init__(self, root):
        self.root = root
        self._cipher = None
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._salt = tk.StringVar()
        self._status = tk.StringVar()
        self._status.set("---")
        self.should_cancel = False

        root.title("Saikey - Encryption/Decryption Tool")
        root.configure(bg="#E8F4FF")

        try:
            icon_img = tk.Image(
                "photo",
                file=self.THIS_FOLDER_G + "/logo/icon.png"
            )
            root.call(
                "wm",
                "iconphoto",
                root._w,
                icon_img
            )
        except Exception:
            pass

        self.menu_bar = tk.Menu(root, bg="#eeeeee", relief=tk.FLAT)

        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Open", command=self.selectfile_callback)
        file_menu.add_separator()
        file_menu.add_command(label="Save Encrypted Key", command=self.save_encrypted_key_callback)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about_dialog)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)

        version_menu = tk.Menu(self.menu_bar, tearoff=0)
        version_menu.add_command(label="About", command=self.show_about_dialog)
        self.menu_bar.add_cascade(label="Version", menu=version_menu)

        root.configure(menu=self.menu_bar)

        self.file_entry_label = tk.Label(
            root,
            text="Enter File Path Or Click SELECT FILE Button",
            bg="#FAC9D0",
            anchor=tk.W
        )


















if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()