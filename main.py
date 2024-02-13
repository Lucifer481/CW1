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

        os.remove(self.user_file)

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
        self.file_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.file_entry = tk.Entry(
            root,
            textvariable=self._file_url,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.file_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.select_btn = tk.Button(
            root,
            text="SELECT FILE",
            command=self.selectfile_callback,
            width=42,
            bg="#1089ff",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT

                    )
        self.select_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.encrypt_btn = tk.Button(
            root,
            text="ENCRYPT",
            command=self.encrypt_callback,
            bg="#ed3833",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.encrypt_btn.grid(
            padx=(15, 6),
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.decrypt_btn = tk.Button(
            root,
            text="DECRYPT",
            command=self.decrypt_callback,
            bg="#00bd56",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.decrypt_btn.grid(
            padx=(6, 15),
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=2,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.reset_btn = tk.Button(
            root,
            text="RESET",
            command=self.reset_callback,
            bg="#aaaaaa",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.reset_btn.grid(
            padx=15,
            pady=(4, 12),
            ipadx=24,
            ipady=6,
            row=8,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.status_label = tk.Label(
            root,
            textvariable=self._status,
            bg="#eeeeee",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350
        )
        self.status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)

# Encrypted key saved
    def save_encrypted_key_callback(self):
        try:
            if self._cipher:
                file_name = os.path.splitext(os.path.basename(self._file_url.get()))[0]
                key_path = self._cipher.save_encrypted_key(file_name)
                self._status.set(f"Encrypted Key Saved Successfully at: {key_path}")
            else:
                self._status.set("No encryption in progress. Cannot save key.")
        except Exception as e:
            self._status.set(e)

    def selectfile_callback(self):
        try:
            name = filedialog.askopenfile()
            self._file_url.set(name.name)
        except Exception as e:
            self._status.set(e)
            self.status_label.update()

    def freeze_comtrols(self):
        self.file_entry.configure(state="disabled")
        self.select_btn.configure(state="disabled")
        self.encrypt_btn.configure(state="disabled")
        self.decrypt_btn.configure(state="disabled")
        self.reset_btn.configure(text="CANCEL", command=self.cancel_callback,
                                 fg="#ed3833", bg="#fafafa")
        self.status_label.update()

    def unfreeze_controls(self):
        self.file_entry.configure(state="normal")
        self.select_btn.configure(state="normal")
        self.encrypt_btn.configure(state="normal")
        self.decrypt_btn.configure(state="normal")
        self.reset_btn.configure(text="RESET", command=self.reset_callback,
                                 fg="#ffffff", bg="#aaaaaa")
        self.status_label.update()

    def encrypt_callback(self):
        self.freeze_control()

        try:
            self._cipher = EncryptionTool(
                self._file_url.get()
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
                self.status.set("Your File has been Encrypted Sucessfully!")
                if self.should_cancel:
                    self._cipher.abort()
                    self._status.set("Encryption has been Cancelled!")
                self._cipher = None
                self.should_cancel = False
        except Exception as e:
                self._status.set(e)
                self.unfreeze_controls()

# Check Key 
    def prompt_for_key(self, prompt_text):
        return tkinter.simpledialog.askstring("Key Prompt", prompt_text, show='*')
    
    def check_key_validity(self, entered_key):
        key_file_path = "filekey.key"

        if not os.path.exists(key_file_path):
            return False

        try:
            with open(key_file_path, "rb") as key_file:
                saved_key = key_file.read()

                cipher_suite = Fernet(saved_key)
                # Attempt to decrypt a piece of ciphertext to check if the key is valid
                cipher_suite.decrypt(cipher_suite.encrypt(b"test"))

                return True
        except InvalidToken:
            return False
        except Exception as e:
            print(f"Error checking key validity: {e}")
            return False
        
# Decrypt call
    def decrypt_callback(self):
        self.freeze_controls()

        key_input = self.prompt_for_key("Enter Encryption Key for Decryption")
        if key_input is None:
            self.unfreeze_controls()
            return

        try:
            self._cipher = EncryptionTool(
                self._file_url.get(),
                key_input,
                self._salt.get()
            )
            is_valid_key = self.check_key_validity(key_input)
            if not is_valid_key:
                self._status.set("Invalid Key! Decryption aborted.")
                self.unfreeze_controls()
                return

            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")

            os.remove(self._file_url.get())

            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(e)

        self.unfreeze_controls()

    def reset_callback(self):
        self._cipher = None
        self._file_url.set("")
        self._secret_key.set("")
        self._salt.set("")
        self._status.set("---")

    def cancel_callback(self):
        self.should_cancel = True

    def show_about_dialog(self):
        messagebox.showinfo(
            "About",
            "Saikey\nVersion 1.0 \n\nA simple file encryption/decryption tool."
        )




    

















