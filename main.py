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

