# -*- coding: utf-8 -*-
"""
Created on Fri Oct 27 14:31:11 2017

@author: ScottRoberts
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.asymmetric as asymm


path = "/Users/ScottRoberts/Desktop/CSULB/CECS 378 Computer Security/Encryption_Assignment/"

def Myencrypt(M, key):
    # If the key length is too short, return with error
    if(len(key) < 32):
        return "Your key length is too short: " + str(len(key))
    
    # Class object to perform AES encryption with CBC-MAC integrity checks
    aesccm = AESCCM(key)
    
    # Check if the Message is not a byte array.
    if(not isinstance(M, bytes)):
        data = M.encode('utf-8')
    else:
        data = M
    
    # OS entropy pool IV
    IV = os.urandom(13)     
    
    # Encrypt using the AES/CBC-MAC object
    ct = aesccm.encrypt(IV, data, "None".encode('utf-8'))
    return ct, IV

def Mydecrypt(ct, IV, key):
    # If the key length is too short, return with error
    if(len(key) < 32):
        return "Your key length is too short: " + str(len(key))
    
    # Decrypt using the AES/CBC-MAC object
    aesccm = AESCCM(key)
    M = aesccm.decrypt(IV, ct, "None".encode('utf-8'))
    return M


def MyfileEncrypt(filepath):
    # Generate internal key
    key = AESCCM.generate_key(bit_length=256)
    
    # Parse the filepath to name and extension
    filename, ext = os.path.splitext(filepath)
    
    # Read the file and save the byte data to "data"
    with open(filepath, 'rb') as f:
        data = f.read()
        f.close()
    
    # Get cyphertext and IV by encrypting the byte data
    ct, IV = Myencrypt(data, key)
    
    # Write to the new "Encrypted" file
    with open(filename + "_ENCRYPTED" + ext, 'wb') as f:
        f.write(ct)
        f.close()
        
    return ct, IV, key, ext

def MyfileDecrypt(ct, IV, key, fileName, ext):
    # Call Mydecrypt to get the byte string
    data = Mydecrypt(ct, IV, key)
    
    # Write the byte string to the decrypted file
    with open(fileName + "_DECRYPTED" + ext,"wb") as f:
        f.write(data)
        f.close()
        
    return data

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    # Encrypt the file to get the internal key
    C, IV, key, ext = MyfileEncrypt(filepath)
    
    # Load the public key
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
                )
    # Encrypt the key to get RSACipher
    RSACipher = public_key.encrypt(
            key, 
            asymm.padding.OAEP(
                    mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None 
                    )
            )
    
    return RSACipher, C, IV, ext
    
    
def MyRSADecrypt(RSACipher, C, IV, filepath, ext, RSA_Privatekey_filepath):
    # Load the private key
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
        
    # Decrypt the RSACipher to get the internal key
    key = private_key.decrypt(
        RSACipher,
        asymm.padding.OAEP(
                mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
        )
    )
    # Decrypt using the internal key
    MyfileDecrypt(C, IV, key, filepath, ext)
        

def generateKeys():
    # Generate the original key
    key = rsa.generate_private_key(backend=default_backend(), 
                                   public_exponent=65537,
                                      key_size=2048)
    
    # Craft the private key from the original key
    private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
    
    # Write the private key to the PEM file
    with open((path + "private_key.pem"), 'wb') as file:
        file.write(private_pem)
        file.close()
    
    # Craft the public key from the original key
    public = key.public_key()
    public_pem = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    # Write the public key to the PEM file
    with open((path + "public_key.pem"), 'wb') as file:
        file.write(public_pem)
        file.close() 
    return

# Test Case 4: RSA Encryption/Decryption with .jpg File
def RSADriver():
    RSACipher, ct, IV, ext = MyRSAEncrypt((path + "smiley_face.jpg"), (path + "public_key.pem"))
    MyRSADecrypt(RSACipher, ct, IV, (path + "smiley_face_ENCRYPTED"), ext, (path + "private_key.pem"))
    return
    
    
# Test Case 3: Encryption/Decryption with .jpg file
def JPGDriver():
    fileName = (path + "smiley_face.jpg")
    ct, IV, key, ext = MyfileEncrypt(fileName)
    fileName2 = (path + "smiley_face_ENCRYPTED")
    MyfileDecrypt(ct, IV, key, fileName2, ext)
    return
    
# Test Case 2: Encryption/Decryption with .txt file
def TXTDriver():
    fileName = (path + "test_File.txt")
    ct, IV, key, ext = MyfileEncrypt(fileName)
    fileName2 = (path + "test_File_ENCRYPTED")
    MyfileDecrypt(ct, IV, key, fileName2, ext)
    return

# Test Case 1: Encryption/Decryption with string message
def STRDriver():
    key = os.urandom(32)
    M = "These are not the droids you are looking for..."
    print("\n" + M)
    ct, IV = Myencrypt(M, key)
    print("\n" + "The IV is: ", IV)
    print("\n" + "The Cipher-text is: ", ct)
    message = Mydecrypt(ct, IV, key)
    m = message.decode("utf-8")
    print("\n" + m)
    return