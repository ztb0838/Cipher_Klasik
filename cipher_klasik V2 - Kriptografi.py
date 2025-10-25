# -*- coding: utf-8 -*-
"""
Tugas 1: Implementasi Cipher Klasik (Versi Interaktif)
Nama: Wildan Hanif, Zulfitrah Akbar
NIM: [20123074], [20123084]
Mata Kuliah: Kriptografi
"""

import numpy as np
import os # Tambahkan ini untuk membersihkan layar

# =============================================================================
# FUNGSI-FUNGSI CIPHER (Tidak diubah, sudah bagus)
# =============================================================================

# 1. CAESAR CIPHER
def caesar_encrypt(text, shift):
    """
    Mengenkripsi teks menggunakan Caesar Cipher.
    Hanya karakter alfabet yang dienkripsi, karakter lain diabaikan.
    """
    result = ""
    for char in text:
        if char.isalpha(): # Hanya proses huruf
            start = ord('A') if char.isupper() else ord('a')
            # Rumus Enkripsi Caesar: C = (P + K) mod 26
            encrypted_char = chr((ord(char) - start + shift) % 26 + start)
            result += encrypted_char
        else:
            result += char # Karakter non-alfabet tidak diubah
    return result

def caesar_decrypt(ciphertext, shift):
    """
    Mendekripsi teks dari Caesar Cipher.
    Ini sama dengan enkripsi dengan pergeseran negatif.
    """
    # Rumus Dekripsi Caesar: P = (C - K) mod 26
    return caesar_encrypt(ciphertext, -shift)

# 2. AFFINE CIPHER
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse tidak ada')
    return x % m

def affine_encrypt(text, a, b):
    if egcd(a, 26)[0] != 1:
        raise ValueError("'a' harus koprima dengan 26.")
        
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            # Rumus Enkripsi Affine: C = (a*P + b) mod 26
            encrypted_char = chr(((a * (ord(char) - start) + b) % 26) + start)
            result += encrypted_char
        else:
            result += char
    return result

def affine_decrypt(ciphertext, a, b):
    if egcd(a, 26)[0] != 1:
        raise ValueError("'a' harus koprima dengan 26.")
        
    result = ""
    mod_inv_a = mod_inverse(a, 26)
    
    for char in ciphertext:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            # Rumus Dekripsi Affine: P = a^-1 * (C - b) mod 26
            decrypted_char = chr((mod_inv_a * (ord(char) - start - b)) % 26 + start)
            result += decrypted_char
        else:
            result += char
    return result

# 3. VIGENERE CIPHER
def vigenere_encrypt(text, key):
    result = ""
    key_index = 0
    key = key.lower()
    
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            encrypted_char = chr((ord(char) - start + shift) % 26 + start)
            result += encrypted_char
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(ciphertext, key):
    result = ""
    key_index = 0
    key = key.lower()
    
    for char in ciphertext:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            decrypted_char = chr((ord(char) - start - shift) % 26 + start)
            result += decrypted_char
            key_index += 1
        else:
            result += char
    return result

# 4. PLAYFAIR CIPHER
def generate_playfair_matrix(key):
    key = key.upper().replace("J", "I")
    matrix_str = ""
    for char in key:
        if char not in matrix_str and char.isalpha():
            matrix_str += char
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in matrix_str:
            matrix_str += char
    return np.array(list(matrix_str)).reshape(5, 5)

def find_position(matrix, char):
    if char == "J":
        char = "I"
    pos = np.where(matrix == char.upper())
    return pos[0][0], pos[1][0]

def playfair_process(text, matrix, mode):
    # Mode: 1 for encrypt, -1 for decrypt
    text = text.upper().replace("J", "I")
    # Hanya proses huruf, buang yang lain
    processed_text = "".join(filter(str.isalpha, text))

    if mode == 1: # Enkripsi
        # Siapkan pasangan huruf
        pairs = []
        i = 0
        while i < len(processed_text):
            a = processed_text[i]
            if i + 1 == len(processed_text):
                b = 'X'
                i += 1
            else:
                b = processed_text[i+1]
            
            if a == b:
                pairs.append(a + 'X')
                i += 1
            else:
                pairs.append(a + b)
                i += 2
    else: # Dekripsi
        pairs = [processed_text[i:i+2] for i in range(0, len(processed_text), 2)]

    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        if row1 == row2:
            result += matrix[row1][(col1 + mode) % 5]
            result += matrix[row2][(col2 + mode) % 5]
        elif col1 == col2:
            result += matrix[(row1 + mode) % 5][col1]
            result += matrix[(row2 + mode) % 5][col2]
        else:
            result += matrix[row1][col2]
            result += matrix[row2][col1]
    return result

def playfair_encrypt(text, matrix):
    return playfair_process(text, matrix, 1)

def playfair_decrypt(ciphertext, matrix):
    return playfair_process(ciphertext, matrix, -1)

# 5. HILL CIPHER (2x2 matrix)
def hill_encrypt(text, key_matrix):
    text = text.upper().replace(" ", "")
    processed_text = "".join(filter(str.isalpha, text))
    if len(processed_text) % 2 != 0:
        processed_text += 'X'
    
    result = ""
    for i in range(0, len(processed_text), 2):
        pair = [ord(processed_text[i]) - 65, ord(processed_text[i+1]) - 65]
        res = np.dot(key_matrix, pair) % 26
        result += chr(res[0] + 65) + chr(res[1] + 65)
    return result

def matrix_mod_inverse(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    matrix_adj = np.array([[matrix[1][1], -matrix[0][1]], [-matrix[1][0], matrix[0][0]]])
    inv_matrix = (det_inv * matrix_adj) % modulus
    return inv_matrix.astype(int)

def hill_decrypt(ciphertext, key_matrix):
    try:
        inv_matrix = matrix_mod_inverse(key_matrix, 26)
    except:
        return "Error: Matriks kunci tidak dapat di-inverse. Determinan mungkin 0 atau kelipatan 13."
        
    result = ""
    for i in range(0, len(ciphertext), 2):
        pair = [ord(ciphertext[i]) - 65, ord(ciphertext[i+1]) - 65]
        res = np.dot(inv_matrix, pair) % 26
        result += chr(res[0] + 65) + chr(res[1] + 65)
    return result

# =============================================================================
# FUNGSI BARU UNTUK INTERAKSI DAN SIMPAN FILE
# =============================================================================
def clear_screen():
    """Membersihkan layar terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')

def save_to_file(content):
    """Menyimpan hasil ke file .txt."""
    try:
        filename = input("Masukkan nama file untuk menyimpan (contoh: hasil.txt): ")
        if not filename.endswith('.txt'):
            filename += '.txt'
        with open(filename, 'w') as f:
            f.write(content)
        print(f"✅ Hasil berhasil disimpan ke file '{filename}'")
    except Exception as e:
        print(f"❌ Gagal menyimpan file: {e}")

def main_interactive():
    """Fungsi utama untuk menjalankan program secara interaktif."""
    while True:
        clear_screen()
        print("===== PROGRAM CIPHER KLASIK =====")
        print("Pilih Cipher:")
        print("1. Caesar Cipher")
        print("2. Affine Cipher")
        print("3. Vigenere Cipher")
        print("4. Playfair Cipher")
        print("5. Hill Cipher")
        print("0. Keluar")
        
        choice = input("Masukkan pilihan Anda: ")
        
        if choice == '0':
            print("Terima kasih telah menggunakan program ini!")
            break
            
        elif choice in ['1', '2', '3', '4', '5']:
            mode_choice = input("Pilih mode (1: Enkripsi, 2: Dekripsi): ")
            if mode_choice not in ['1', '2']:
                print("Pilihan mode tidak valid.")
                input("Tekan Enter untuk melanjutkan...")
                continue
            
            text = input("Masukkan teks: ")
            result = ""
            
            # --- Caesar Cipher ---
            if choice == '1':
                try:
                    shift = int(input("Masukkan kunci pergeseran (angka): "))
                    if mode_choice == '1':
                        result = caesar_encrypt(text, shift)
                        print(f"\nCiphertext: {result}")
                    else:
                        result = caesar_decrypt(text, shift)
                        print(f"\nPlaintext: {result}")
                except ValueError:
                    print("Kunci harus berupa angka.")
            
            # --- Affine Cipher ---
            elif choice == '2':
                try:
                    a = int(input("Masukkan kunci a (harus koprima dengan 26): "))
                    b = int(input("Masukkan kunci b: "))
                    if mode_choice == '1':
                        result = affine_encrypt(text, a, b)
                        print(f"\nCiphertext: {result}")
                    else:
                        result = affine_decrypt(text, a, b)
                        print(f"\nPlaintext: {result}")
                except (ValueError, Exception) as e:
                    print(f"Error: {e}")
            
            # --- Vigenere Cipher ---
            elif choice == '3':
                key = input("Masukkan kunci (kata): ")
                if not key.isalpha():
                    print("Kunci Vigenere harus berupa kata (huruf saja).")
                else:
                    if mode_choice == '1':
                        result = vigenere_encrypt(text, key)
                        print(f"\nCiphertext: {result}")
                    else:
                        result = vigenere_decrypt(text, key)
                        print(f"\nPlaintext: {result}")
            
            # --- Playfair Cipher ---
            elif choice == '4':
                key = input("Masukkan kunci (kata): ")
                matrix = generate_playfair_matrix(key)
                print("Matriks Playfair yang dihasilkan:")
                print(matrix)
                if mode_choice == '1':
                    result = playfair_encrypt(text, matrix)
                    print(f"\nCiphertext: {result}")
                else:
                    result = playfair_decrypt(text, matrix)
                    print(f"\nPlaintext: {result}")
            
            # --- Hill Cipher ---
            elif choice == '5':
                print("Masukkan matriks kunci 2x2 (4 angka dipisah spasi, cth: 3 3 2 5): ")
                try:
                    key_vals = list(map(int, input().split()))
                    if len(key_vals) != 4:
                        raise ValueError("Harus memasukkan 4 angka.")
                    key_matrix = np.array(key_vals).reshape(2, 2)
                    
                    # Cek determinan
                    det = int(np.round(np.linalg.det(key_matrix)))
                    if det == 0 or np.gcd(det, 26) != 1:
                         print("Matriks tidak valid. Determinan tidak boleh 0 atau memiliki faktor persekutuan dengan 26.")
                    else:
                        if mode_choice == '1':
                            result = hill_encrypt(text, key_matrix)
                            print(f"\nCiphertext: {result}")
                        else:
                            result = hill_decrypt(text, key_matrix)
                            print(f"\nPlaintext: {result}")
                except ValueError as e:
                    print(f"Input matriks tidak valid: {e}")

            # --- Simpan ke File ---
            if result:
                save_choice = input("\nApakah Anda ingin menyimpan hasil ini ke file? (y/n): ").lower()
                if save_choice == 'y':
                    save_to_file(result)

            input("\nTekan Enter untuk kembali ke menu utama...")

        else:
            print("Pilihan tidak valid. Silakan coba lagi.")
            input("Tekan Enter untuk melanjutkan...")

if __name__ == '__main__':
    main_interactive()