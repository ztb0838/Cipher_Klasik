# -*- coding: utf-8 -*-
"""
Tugas 1: Implementasi Cipher Klasik
Nama: Wildan Hanif, Zulfitrah Akbar
NIM: [20123074], [20123084]
Mata Kuliah: Kriptografi

Program ini mengimplementasikan tiga algoritma cipher klasik:
1. Caesar Cipher
2. Affine Cipher
3. Vigenere Cipher
"""

import numpy as np

# =============================================================================
# 1. CAESAR CIPHER
# =============================================================================
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

# =============================================================================
# 2. AFFINE CIPHER
# =============================================================================
def egcd(a, b):
    """
    Extended Euclidean Algorithm untuk mencari modular inverse.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    """
    Mencari modular inverse dari a mod m.
    Diperlukan untuk dekripsi Affine Cipher.
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse tidak ada')
    return x % m

def affine_encrypt(text, a, b):
    """
    Mengenkripsi teks menggunakan Affine Cipher.
    Parameter 'a' harus koprima dengan 26.
    """
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
    """
    Mendekripsi teks dari Affine Cipher.
    """
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

# =============================================================================
# 3. VIGENERE CIPHER
# =============================================================================
def vigenere_encrypt(text, key):
    """
    Mengenkripsi teks menggunakan Vigenere Cipher.
    """
    result = ""
    key_index = 0
    key = key.lower() # Standarisasi kunci ke huruf kecil
    
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            # Tentukan pergeseran dari huruf kunci saat ini
            shift = ord(key[key_index % len(key)]) - ord('a')
            
            # Enkripsi karakter
            encrypted_char = chr((ord(char) - start + shift) % 26 + start)
            result += encrypted_char
            
            # Pindah ke huruf kunci berikutnya
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(ciphertext, key):
    """
    Mendekripsi teks dari Vigenere Cipher.
    """
    result = ""
    key_index = 0
    key = key.lower()
    
    for char in ciphertext:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            # Tentukan pergeseran (negatif) dari huruf kunci
            shift = ord(key[key_index % len(key)]) - ord('a')
            
            # Dekripsi karakter
            decrypted_char = chr((ord(char) - start - shift) % 26 + start)
            result += decrypted_char
            
            key_index += 1
        else:
            result += char
    return result

# =============================================================================
# 4. PLAYFAIR CIPHER
# =============================================================================
def generate_playfair_matrix(key):
    """
    Membuat matriks 5x5 untuk Playfair Cipher dari kunci.
    """
    key = key.upper().replace("J", "I")
    matrix = ""
    for char in key:
        if char not in matrix and char.isalpha():
            matrix += char
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in matrix:
            matrix += char
    return np.array(list(matrix)).reshape(5, 5)

def find_position(matrix, char):
    """
    Mencari posisi (baris, kolom) dari huruf dalam matriks Playfair.
    """
    if char == "J":
        char = "I"
    pos = np.where(matrix == char)
    return pos[0][0], pos[1][0]

def playfair_encrypt(text, matrix):
    """
    Mengenkripsi teks menggunakan Playfair Cipher.
    """
    text = text.upper().replace("J", "I").replace(" ", "")
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        if row1 == row2:
            result += matrix[row1][(col1+1) % 5]
            result += matrix[row2][(col2+1) % 5]
        elif col1 == col2:
            result += matrix[(row1+1) % 5][col1]
            result += matrix[(row2+1) % 5][col2]
        else:
            result += matrix[row1][col2]
            result += matrix[row2][col1]
    return result

def playfair_decrypt(ciphertext, matrix):
    """
    Mendekripsi teks dari Playfair Cipher.
    """
    result = ""
    i = 0
    while i < len(ciphertext):
        a = ciphertext[i]
        b = ciphertext[i+1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            result += matrix[row1][(col1-1) % 5]
            result += matrix[row2][(col2-1) % 5]
        elif col1 == col2:
            result += matrix[(row1-1) % 5][col1]
            result += matrix[(row2-1) % 5][col2]
        else:
            result += matrix[row1][col2]
            result += matrix[row2][col1]
        i += 2
    return result

# =============================================================================
# 5. HILL CIPHER (2x2 matrix)
# =============================================================================
def hill_encrypt(text, key_matrix):
    """
    Mengenkripsi teks menggunakan Hill Cipher (matriks 2x2).
    """
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += 'X'
    result = ""
    for i in range(0, len(text), 2):
        pair = [ord(text[i]) - 65, ord(text[i+1]) - 65]
        res = np.dot(key_matrix, pair) % 26
        result += chr(res[0] + 65) + chr(res[1] + 65)
    return result

def matrix_mod_inverse(matrix, modulus):
    """
    Menghitung invers matriks 2x2 dalam modulo tertentu.
    """
    det = int(np.round(np.linalg.det(matrix))) % modulus
    det_inv = pow(det, -1, modulus)
    matrix_adj = np.array([[matrix[1][1], -matrix[0][1]],
                           [-matrix[1][0], matrix[0][0]]])
    return (det_inv * matrix_adj) % modulus

def hill_decrypt(ciphertext, key_matrix):
    """
    Mendekripsi teks dari Hill Cipher (matriks 2x2).
    """
    inv_matrix = matrix_mod_inverse(key_matrix, 26)
    result = ""
    for i in range(0, len(ciphertext), 2):
        pair = [ord(ciphertext[i]) - 65, ord(ciphertext[i+1]) - 65]
        res = np.dot(inv_matrix, pair) % 26
        result += chr(int(res[0]) + 65) + chr(int(res[1]) + 65)
    return result

# =============================================================================
# FUNGSI UTAMA UNTUK DEMONSTRASI
# =============================================================================
def main():
    print("===== DEMO PROGRAM CIPHER KLASIK =====")
    
    # Contoh Plaintext dan Kunci
    plaintext = "Hello World! This is a secret message."
    
    # --- Caesar Cipher ---
    print("\n--- 1. Caesar Cipher ---")
    caesar_key = 3
    print(f"Plaintext: {plaintext}")
    print(f"Kunci (Shift): {caesar_key}")
    encrypted_caesar = caesar_encrypt(plaintext, caesar_key)
    print(f"Ciphertext: {encrypted_caesar}")
    decrypted_caesar = caesar_decrypt(encrypted_caesar, caesar_key)
    print(f"Decrypted: {decrypted_caesar}")
    
    # --- Affine Cipher ---
    print("\n--- 2. Affine Cipher ---")
    affine_key_a = 5
    affine_key_b = 8
    print(f"Plaintext: {plaintext}")
    print(f"Kunci (a, b): ({affine_key_a}, {affine_key_b})")
    try:
        encrypted_affine = affine_encrypt(plaintext, affine_key_a, affine_key_b)
        print(f"Ciphertext: {encrypted_affine}")
        decrypted_affine = affine_decrypt(encrypted_affine, affine_key_a, affine_key_b)
        print(f"Decrypted: {decrypted_affine}")
    except ValueError as e:
        print(f"Error: {e}")

    # --- Vigenere Cipher ---
    print("\n--- 3. Vigenere Cipher ---")
    vigenere_key = "UNIVERSITAS"
    print(f"Plaintext: {plaintext}")
    print(f"Kunci: {vigenere_key}")
    encrypted_vigenere = vigenere_encrypt(plaintext, vigenere_key)
    print(f"Ciphertext: {encrypted_vigenere}")
    decrypted_vigenere = vigenere_decrypt(encrypted_vigenere, vigenere_key)
    print(f"Decrypted: {decrypted_vigenere}")

     # --- Playfair Cipher ---
    print("\n--- 4. Playfair Cipher ---")
    playfair_key = "KEYWORD"
    playfair_matrix = generate_playfair_matrix(playfair_key)
    playfair_text = "HELLO"
    print(f"Plaintext: {playfair_text}")
    print(f"Kunci: {playfair_key}")
    print(f"Matriks Kunci Playfair:\n{playfair_matrix}")
    encrypted_playfair = playfair_encrypt(playfair_text, playfair_matrix)
    print(f"Ciphertext: {encrypted_playfair}")
    print(f"Decrypted: {playfair_decrypt(encrypted_playfair, playfair_matrix)}")

    # --- Hill Cipher ---
    print("\n--- 5. Hill Cipher ---")
    hill_key = np.array([[3, 3],
                         [2, 5]])
    hill_text = "HI"
    print(f"Plaintext: {hill_text}")
    print(f"Matriks Kunci Hill:\n{hill_key}")
    encrypted_hill = hill_encrypt(hill_text, hill_key)
    print(f"Ciphertext: {encrypted_hill}")
    print(f"Decrypted: {hill_decrypt(encrypted_hill, hill_key)}")

if __name__ == '__main__':
    main()