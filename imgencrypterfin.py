from PIL import Image
import numpy as np

# Convert a string key to a byte array (sequence of numerical values)
def string_to_key_bytes(key: str) -> bytes:
    return key.encode('utf-8')  # Convert string to bytes

# XOR encryption/decryption function with string key
def xor_crypt(pixel_array: np.ndarray, key_string: str) -> np.ndarray:
    key_bytes = string_to_key_bytes(key_string)
    key_length = len(key_bytes)
    
    # Create a flat array of pixel data
    flat_pixels = pixel_array.flatten()
    
    # XOR each pixel with the corresponding key byte (loop through the key)
    encrypted_pixels = np.array([pixel ^ key_bytes[i % key_length] for i, pixel in enumerate(flat_pixels)])
    
    # Reshape the flat array back into the original shape of the image
    encrypted_array = encrypted_pixels.reshape(pixel_array.shape)
    
    return encrypted_array.astype(np.uint8)

# Function to encrypt the image using XOR
def encrypt_image_xor(image_path: str, key_string: str, output_path: str):
    # Open the image
    img = Image.open(image_path)
    img = img.convert('RGB')

    # Convert image to numpy array
    img_array = np.array(img)

    # Encrypt the image using XOR
    encrypted_array = xor_crypt(img_array, key_string)

    # Create encrypted image from the modified array
    encrypted_img = Image.fromarray(encrypted_array)

    # Save the encrypted image with the same name (in a valid image format)
    encrypted_img.save(output_path + ".png")
    
    print(f"Image encrypted and saved as '{output_path}.png'")

# Function to decrypt the image using XOR (same as encryption)
def decrypt_image_xor(encrypted_path: str, key_string: str, output_path: str):
    # Open the encrypted image
    encrypted_img = Image.open(encrypted_path)
    encrypted_img = encrypted_img.convert('RGB')

    # Convert encrypted image to numpy array
    encrypted_array = np.array(encrypted_img)

    # Decrypt the image using XOR (same as encryption)
    decrypted_array = xor_crypt(encrypted_array, key_string)

    # Create decrypted image from the modified array
    decrypted_img = Image.fromarray(decrypted_array)
    
    # Save the decrypted image with the same name (in a valid image format)
    decrypted_img.save(output_path + ".png")
    
    print(f"Image decrypted and saved as '{output_path}.png'")

# Get user inputs for image path and key
operation = input("Do you want to 'encrypt' or 'decrypt' the image? ").strip().lower()
image_path = input("Enter the image path: ").strip()
key_string = input("Enter the encryption/decryption key (string): ").strip()
output_path = input("Enter the output image path (without extension): ").strip()

# Perform encryption or decryption based on user choice
if operation == 'encrypt':
    encrypt_image_xor(image_path, key_string, output_path)
elif operation == 'decrypt':
    decrypt_image_xor(image_path, key_string, output_path)
else:
    print("Invalid operation. Please choose either 'encrypt' or 'decrypt'.")
