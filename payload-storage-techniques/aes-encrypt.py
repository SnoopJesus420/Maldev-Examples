import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

# Constants
AES_KEY_SIZE = 32  # 256-bit key
AES_IV_SIZE = 16   # 128-bit IV (block size for AES)

def generate_random_bytes(size):
    """Generate random bytes of specified size."""
    return secrets.token_bytes(size)

def print_hex_data(name, data):
    """Print data as a hex char array in C syntax."""
    print(f"unsigned char {name}[] = {{")
    for i, byte in enumerate(data):
        if i % 16 == 0:
            print("\t", end="")
        if i < len(data) - 1:
            print(f"0x{byte:02X}, ", end="")
        else:
            print(f"0x{byte:02X} ", end="")
        if (i + 1) % 16 == 0:
            print()
    print("};\n\n")

def aes_encrypt(plaintext, key, iv):
    """Encrypt plaintext using AES-CBC with PKCS7 padding."""
    try:
        # Ensure key and IV are of correct length
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")
        if len(iv) != AES_IV_SIZE:
            raise ValueError(f"IV must be {AES_IV_SIZE} bytes")

        # Apply PKCS7 padding
        padder = padding.PKCS7(AES_IV_SIZE * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Set up AES-CBC cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
    except Exception as e:
        print(f"[!] Encryption failed: {str(e)}")
        return None

def simple_encryption(input_file, output_file, key=None, iv=None):
    """Encrypt a .bin file and save the encrypted data to another .bin file."""
    try:
        # Generate random key and IV if not provided
        key = key or generate_random_bytes(AES_KEY_SIZE)
        iv = iv or generate_random_bytes(AES_IV_SIZE)

        # Read the input .bin file
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        if not plaintext:
            print("[!] Input file is empty or could not be read")
            return False, None, None, None

        # Encrypt the data
        ciphertext = aes_encrypt(plaintext, key, iv)
        if ciphertext is None:
            return False, None, None, None

        # Write the encrypted data to the output .bin file
        with open(output_file, 'wb') as f:
            f.write(ciphertext)

        return True, ciphertext, key, iv
    except Exception as e:
        print(f"[!] Error processing file: {str(e)}")
        return False, None, None, None

def main():
    """Main function to demonstrate encryption of a .bin file."""
    input_file = "input.bin"
    output_file = "output.bin"

    # Ensure input file exists
    if not os.path.exists(input_file):
        print(f"[!] Input file '{input_file}' does not exist")
        return

    # Perform encryption
    success, ciphertext, key, iv = simple_encryption(input_file, output_file)
    if success:
        print(f"[+] Successfully encrypted '{input_file}' to '{output_file}'")
        print(f"[+] Key size: {len(key)} bytes")
        print(f"[+] IV size: {len(iv)} bytes")
        print(f"[+] Ciphertext size: {len(ciphertext)} bytes")

        # Print hex data
        print_hex_data("key", key)
        print_hex_data("iv", iv)
        print_hex_data("ciphertext", ciphertext)
    else:
        print(f"[!] Failed to encrypt '{input_file}'")

if __name__ == "__main__":
    main()
