from Crypto.Cipher import DES3  #provide DES encryption algorithm
from Crypto.PublicKey import RSA #PROVIDE RSA key generation
from Crypto.Cipher import PKCS1_OAEP # RSA encryption
from Crypto.Random import get_random_bytes #generate random bytes

def generate_rsa_key_pair():
    key = RSA.generate(2048) #generate RSA key object with size 2048
    private_key = key.export_key() #Exports the private key in PEM format
    public_key = key.publickey().export_key() #Exports the public key in PEM format.
    return private_key, public_key 
def encrypt_with_rsa(public_key, data):
    key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(key) # Creates a new RSA encryption cipher with Optimal Asymmetric Encryption Padding
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def encrypt_with_3des(key, data):
    cipher_3des = DES3.new(key, DES3.MODE_ECB) #Creates a new Triple DES encryption cipher in Electronic Codebook (ECB) mode.
    padded_data = data + b"\0" * (8 - len(data) % 8)  # Padding to multiple of 8 bytes
    encrypted_data = cipher_3des.encrypt(padded_data) #Encrypts the padded data using Triple DES.
    return encrypted_data
def decrypt_with_rsa(private_key, encrypted_data):
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data

def decrypt_with_3des(key, encrypted_data):
    cipher_3des = DES3.new(key, DES3.MODE_ECB)
    decrypted_data = cipher_3des.decrypt(encrypted_data)
    return decrypted_data.rstrip(b"\0") #remove padding
if __name__ == "__main__":
    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # Generate a random 3DES key
    des3_key = get_random_bytes(24)

    # Data to be encrypted
    email_content = b"Your sensitive email content goes here ."

    # Encrypt with 3DES using the generated key
    encrypted_email_content = encrypt_with_3des(des3_key, email_content)

    # Encrypt the 3DES key with RSA public key
    encrypted_des3_key = encrypt_with_rsa(public_key, des3_key)

    # Print the keys and encrypted email
    print("RSA Private Key:")
    print(private_key.decode('utf-8'))

    print("\nRSA Public Key:")
    print(public_key.decode('utf-8'))

    print("\n3DES Key:")
    print(des3_key.hex())

    print("\nEncrypted 3DES Key:")
    print(encrypted_des3_key.hex())

    print("\nOriginal Email Content:", email_content.decode('utf-8'))
    print("\nEncrypted Email Content:")
    print(encrypted_email_content.hex())
 
     decrypted_des3_key = decrypt_with_rsa(private_key, encrypted_des3_key)  #decrypt the 3DES key with RSA private key
    decrypted_email_content = decrypt_with_3des(decrypted_des3_key, encrypted_email_content) #Decrypt the email content with the decrypted 3DES key
    
    print("\nDecrypted Email Content:", decrypted_email_content.decode('utf-8'))




