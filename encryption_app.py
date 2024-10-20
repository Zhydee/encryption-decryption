import tkinter as tk
from tkinter import ttk, scrolledtext
import base64
from Crypto.Cipher import AES  # Make sure to install pycryptodome

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
    if padding < key_len:
        text += '_' * padding
    grid = [text[i:i + key_len] for i in range(0, len(text), key_len)]
    
    # Create a sorted order for the columns based on the key
    order = sorted(range(key_len), key=lambda x: key[x])
    
    # Read columns in the order specified by the key
    cipher = ''.join(''.join(row[i] for row in grid) for i in order)
    return cipher

def row_transposition_decrypt(cipher, key):
    key_len = len(key)
    num_rows = len(cipher) // key_len
    grid = [[''] * key_len for _ in range(num_rows)]
    
    # Create a sorted order for the columns based on the key
    order = sorted(range(key_len), key=lambda x: key[x])
    
    col_index = 0
    # Fill grid based on the original column order
    for col in order:
        for row in range(num_rows):
            grid[row][col] = cipher[col_index]
            col_index += 1
            
    # Read the grid row-wise to get the decrypted text
    plain_text = ''.join(''.join(row) for row in grid)
    return plain_text.replace('_', '')  # Remove padding

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

# Vigenère Cipher Functions
def vigenere_encrypt(text, key):
    key = key.upper()
    encrypted = []
    key_index = 0
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                encrypted.append(chr((ord(char) + shift - 65) % 26 + 65))
            elif char.islower():
                encrypted.append(chr((ord(char) + shift - 97) % 26 + 97))
            key_index += 1
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    decrypted = []
    key_index = 0
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                decrypted.append(chr((ord(char) - shift - 65) % 26 + 65))
            elif char.islower():
                decrypted.append(chr((ord(char) - shift - 97) % 26 + 97))
            key_index += 1
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# GUI Setup
def encrypt_text():
    method = algorithm_choice.get()
    text = input_text.get("1.0", 'end-1c').strip()
    key = key_input.get().strip()
    
    try:
        if method == 'Caesar Cipher':
            output = caesar_encrypt(text, int(key))
        elif method == 'Rail Fence Cipher':
            output = rail_fence_encrypt(text, int(key))
        elif method == 'Row Transposition Cipher':
            output = row_transposition_encrypt(text, list(map(int, key.split(','))))
        elif method == 'AES':
            output = aes_encrypt(text, key)
        elif method == 'Vigenère Cipher':
            output = vigenere_encrypt(text, key)
        else:
            raise ValueError("Select a valid encryption method.")
        
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, output)
    
    except Exception as e:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Error: {str(e)}")

def decrypt_text():
    method = algorithm_choice.get()
    text = input_text.get("1.0", 'end-1c').strip()
    key = key_input.get().strip()
    
    try:
        if method == 'Caesar Cipher':
            output = caesar_decrypt(text, int(key))
        elif method == 'Rail Fence Cipher':
            output = rail_fence_decrypt(text, int(key))
        elif method == 'Row Transposition Cipher':
            output = row_transposition_decrypt(text, list(map(int, key.split(','))))
        elif method == 'AES':
            output = aes_decrypt(text, key)
        elif method == 'Vigenère Cipher':
            output = vigenere_decrypt(text, key)
        else:
            raise ValueError("Select a valid decryption method.")
        
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, output)
    
    except Exception as e:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Error: {str(e)}")

# GUI Layout
window = tk.Tk()
window.title("Encryption-Decryption App")

# Styling the UI with a minimalist theme
window.configure(bg='#f4f4f9')  # Light background color
window.geometry("400x350")  # Set window size

# Font settings
font_style = ('Helvetica', 12)

# Input text area
input_label = tk.Label(window, text="Enter text:", bg='#f4f4f9', font=font_style)
input_label.pack(pady=5)
input_text = scrolledtext.ScrolledText(window, height=5, wrap=tk.WORD, font=font_style)
input_text.pack(pady=5)

# Key input field
key_label = tk.Label(window, text="Enter Key (if required, comma-separated for Row Transposition):", bg='#f4f4f9', font=font_style)
key_label.pack(pady=5)
key_input = tk.Entry(window, font=font_style)
key_input.pack(pady=5)

# Dropdown for algorithm choice
algorithm_label = tk.Label(window, text="Select Algorithm:", bg='#f4f4f9', font=font_style)
algorithm_label.pack(pady=5)
algorithm_choice = ttk.Combobox(window, values=["Caesar Cipher", "Rail Fence Cipher", "Row Transposition Cipher", "AES", "Vigenère Cipher"], font=font_style)
algorithm_choice.pack(pady=5)

# Encrypt and Decrypt buttons
button_frame = tk.Frame(window, bg='#f4f4f9')
button_frame.pack(pady=10)

encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_text, bg='#ff595e', fg='white', font=font_style, width=10)
encrypt_button.grid(row=0, column=0, padx=10)

decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_text, bg='#1982c4', fg='white', font=font_style, width=10)
decrypt_button.grid(row=0, column=1, padx=10)

# Output text area
output_label = tk.Label(window, text="Output:", bg='#f4f4f9', font=font_style)
output_label.pack(pady=5)
output_text = scrolledtext.ScrolledText(window, height=5, wrap=tk.WORD, font=font_style)
output_text.pack(pady=5)

window.mainloop()
