from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def создать_пару_rsa():
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    return private,private.public_key()
def подписать_документ(документ,закрытый_ключ):
    data=документ.encode("utf-8") if isinstance(документ,str) else документ
    return закрытый_ключ.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
def проверить_подпись(документ,подпись,открытый_ключ):
    try:
        data=документ.encode("utf-8") if isinstance(документ,str) else документ
        открытый_ключ.verify(подпись,data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        return "действительна"
    except InvalidSignature: return "недействительна"
    except (TypeError,ValueError,AttributeError): return "неверный формат"
