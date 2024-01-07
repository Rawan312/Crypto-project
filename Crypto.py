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

