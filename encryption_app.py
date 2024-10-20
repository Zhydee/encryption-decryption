import tkinter as tk
from tkinter import ttk, scrolledtext
from Crypto.Cipher import AES
import base64

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
    
    order = sorted(range(key_len), key=lambda x: key[x])
    
    cipher = ''.join(''.join(row[i] for row in grid) for i in order)
    return cipher

def row_transposition_decrypt(cipher, key):
    key_len = len(key)
    num_rows = len(cipher) // key_len
    grid = [[''] * key_len for _ in range(num_rows)]
    
    order = sorted(range(key_len), key=lambda x: key[x])
    
    col_index = 0
    for col in order:
        for row in range(num_rows):
            grid[row][col] = cipher[col_index]
            col_index += 1
            
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
    text = text.upper()  # Ensure both text and key are uppercase
    key = key.upper()
    encrypted = []
    key_length = len(key)
    
    for i in range(len(text)):
        if text[i].isalpha():  # Only encrypt alphabetic characters
            shift = ord(key[i % key_length]) - ord('A')
            encrypted_char = chr((ord(text[i]) - ord('A') + shift) % 26 + ord('A'))
            encrypted.append(encrypted_char)
        else:
            encrypted.append(text[i])  # Keep non-alphabetic characters as is
    
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()  # Ensure both text and key are uppercase
    key = key.upper()
    decrypted = []
    key_length = len(key)
    
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():  # Only decrypt alphabetic characters
            shift = ord(key[i % key_length]) - ord('A')
            decrypted_char = chr((ord(ciphertext[i]) - ord('A') - shift + 26) % 26 + ord('A'))
            decrypted.append(decrypted_char)
        else:
            decrypted.append(ciphertext[i])  # Keep non-alphabetic characters as is
    
    return ''.join(decrypted)

# GUI Setup with Vigenère Cipher
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

# GUI Styling
window = tk.Tk()
window.title("Encryption-Decryption App")
window.geometry("600x400")
window.configure(bg="#f0f0f0")

# Fonts and Style
header_font = ("Helvetica", 14, "bold")
label_font = ("Helvetica", 11)
button_font = ("Helvetica", 10, "bold")

# Input text area
input_frame = ttk.Frame(window, padding="10")
input_frame.pack(fill='x')

input_label = tk.Label(input_frame, text="Enter text:", font=label_font)
input_label.pack(anchor='w')
input_text = scrolledtext.ScrolledText(input_frame, height=5, font=("Helvetica", 10))
input_text.pack(fill='x')

# Key input field
key_frame = ttk.Frame(window, padding="10")
key_frame.pack(fill='x')

key_label = tk.Label(key_frame, text="Enter Key (if required, comma-separated for Row Transposition):", font=label_font)
key_label.pack(anchor='w')
key_input = tk.Entry(key_frame, font=("Helvetica", 10))
key_input.pack(fill='x')

# Dropdown for algorithm choice
algorithm_frame = ttk.Frame(window, padding="10")
algorithm_frame.pack(fill='x')

algorithm_label = tk.Label(algorithm_frame, text="Select Algorithm:", font=label_font)
algorithm_label.pack(anchor='w')
algorithm_choice = ttk.Combobox(algorithm_frame, values=["Caesar Cipher", "Rail Fence Cipher", "Row Transposition Cipher", "AES", "Vigenère Cipher"], font=("Helvetica", 10))
algorithm_choice.pack(fill='x')

# Encrypt and Decrypt buttons
button_frame = ttk.Frame(window, padding="10")
button_frame.pack(fill='x')

encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_text, bg="#4CAF50", fg="white", font=button_font)
encrypt_button.pack(side='left', padx=10, pady=10)

decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_text, bg="#F44336", fg="white", font=button_font)
decrypt_button.pack(side='left', padx=10, pady=10)

# Output text area
output_frame = ttk.Frame(window, padding="10")
output_frame.pack(fill='x')

output_label = tk.Label(output_frame, text="Output:", font=label_font)
output_label.pack(anchor='w')
output_text = scrolledtext.ScrolledText(output_frame, height=5, font=("Helvetica", 10))
output_text.pack(fill='x')

# Finalize and start the window loop
window.mainloop()

