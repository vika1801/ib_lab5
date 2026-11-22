import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def вычислить_хеш(данные):
    if isinstance(данные,str): данные=данные.encode("utf-8")
    return hashlib.sha256(данные).hexdigest()
def проверить_целостность(данные,ожидаемый_хеш):
    return вычислить_хеш(данные)==ожидаемый_хеш

def создать_ключ_aes():
    return AESGCM.generate_key(bit_length=256)
def aes_зашифровать(данные,ключ):
    if isinstance(данные,str): данные=данные.encode("utf-8")
    nonce=AESGCM.generate_key.__self__ if False else __import__("os").urandom(12)
    encrypted=AESGCM(ключ).encrypt(nonce,данные,None)
    return {"nonce":nonce,"ciphertext":encrypted}
def aes_расшифровать(ciphertext,nonce,ключ):
    return AESGCM(ключ).decrypt(nonce,ciphertext,None)
