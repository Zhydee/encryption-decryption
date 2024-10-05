import tkinter as tk
from tkinter import ttk, scrolledtext
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import string

# Caesar Cipher Functions
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift=3):
    return caesar_encrypt(ciphertext, -shift)

# Rail Fence Cipher Functions
def rail_fence_encrypt(text, key):
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0
    for char in text:
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        rail[row][col] = char
        col += 1
        row += 1 if dir_down else -1
    result = []
    for row in rail:
        result.extend([char for char in row if char != '\n'])
    return "".join(result)

def rail_fence_decrypt(cipher, key):
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    dir_down = None
    row, col = 0, 0
    for _ in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1
    result = []
    row, col = 0, 0
    for _ in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        result.append(rail[row][col])
        col += 1
        row += 1 if dir_down else -1
    return "".join(result)

# Row Transposition Cipher Functions
def row_transposition_encrypt(text, key):
    key_len = len(key)
    text_len = len(text)
    padding = key_len - (text_len % key_len)
    text = text + padding * '_'
    grid = [text[i:i + key_len] for i in range(0, len(text), key_len)]
    cipher = ''.join([''.join(row[i] for row in grid) for i in sorted(range(key_len), key=lambda k: key[k])])
    return cipher

def row_transposition_decrypt(cipher, key):
    key_len = len(key)
    num_rows = len(cipher) // key_len
    grid = [[''] * key_len for _ in range(num_rows)]
    col_index = 0
    for col in sorted(range(key_len), key=lambda k: key[k]):
        for row in range(num_rows):
            grid[row][col] = cipher[col_index]
            col_index += 1
    plain_text = ''.join([''.join(row) for row in grid])
    return plain_text.replace('_', '')

# AES Encryption/Decryption Functions
def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def aes_encrypt(text, key):
    cipher = AES.new(pad(key).encode(), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(text).encode())).decode()

def aes_decrypt(ciphertext, key):
    cipher = AES.new(pad(key).encode(), AES.MODE_ECB)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode().strip()

# RSA Encryption/Decryption Functions
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(text.encode())).decode()

def rsa_decrypt(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode()

# GUI Setup
def encrypt_text():
    method = algorithm_choice.get()
    text = input_text.get("1.0", 'end-1c')
    key = key_input.get()
    
    if method == 'Caesar Cipher':
        output = caesar_encrypt(text, int(key))
    elif method == 'Rail Fence Cipher':
        output = rail_fence_encrypt(text, int(key))
    elif method == 'Row Transposition Cipher':
        output = row_transposition_encrypt(text, list(map(int, key)))
    elif method == 'AES':
        output = aes_encrypt(text, key)
    elif method == 'RSA':
        output = rsa_encrypt(text, rsa_public_key)
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, output)

def decrypt_text():
    method = algorithm_choice.get()
    text = input_text.get("1.0", 'end-1c')
    key = key_input.get()
    
    if method == 'Caesar Cipher':
        output = caesar_decrypt(text, int(key))
    elif method == 'Rail Fence Cipher':
        output = rail_fence_decrypt(text, int(key))
    elif method == 'Row Transposition Cipher':
        output = row_transposition_decrypt(text, list(map(int, key)))
    elif method == 'AES':
        output = aes_decrypt(text, key)
    elif method == 'RSA':
        output = rsa_decrypt(text, rsa_private_key)
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, output)

# RSA Key Generation
rsa_private_key, rsa_public_key = generate_rsa_keys()

# GUI Layout
window = tk.Tk()
window.title("Encryption-Decryption App")

# Input text area
input_label = tk.Label(window, text="Enter text:")
input_label.pack()
input_text = scrolledtext.ScrolledText(window, height=5)
input_text.pack()

# Key input field
key_label = tk.Label(window, text="Enter Key (if required):")
key_label.pack()
key_input = tk.Entry(window)
key_input.pack()

# Dropdown for algorithm choice
algorithm_label = tk.Label(window, text="Select Algorithm:")
algorithm_label.pack()
algorithm_choice = ttk.Combobox(window, values=["Caesar Cipher", "Rail Fence Cipher", "Row Transposition Cipher", "AES", "RSA"])
algorithm_choice.pack()

# Encrypt and Decrypt buttons
encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_text)
encrypt_button.pack()
decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_text)
decrypt_button.pack()

# Output text area
output_label = tk.Label(window, text="Output:")
output_label.pack()
output_text = scrolledtext.ScrolledText(window, height=5)
output_text.pack()

window.mainloop()
