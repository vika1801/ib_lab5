from pathlib import Path
import unittest
from программы.классические_шифры import *
from программы.криптоанализ import частоты, перебор_цезаря
from программы.стеганография import *
from программы.современные_примитивы import *
from программы.электронная_подпись import *
from программы.tls_модель import учебный_tls_сеанс
from данные.параметры_алгоритмов import АЛФАВИТЫ

class CryptoLabTests(unittest.TestCase):
    def test_caesar_ru_roundtrip(self): self.assertEqual(расшифровать_цезарем(зашифровать_цезарем("ТЕСТ",3),3),"ТЕСТ")
    def test_caesar_en_roundtrip(self): self.assertEqual(расшифровать_цезарем(зашифровать_цезарем("Hello",5,АЛФАВИТЫ["en"]),5,АЛФАВИТЫ["en"]),"Hello")
    def test_caesar_shift_modulo(self): self.assertEqual(зашифровать_цезарем("А",len(АЛФАВИТЫ["ru"])), "А")
    def test_caesar_large_shift(self): self.assertEqual(зашифровать_цезарем("А",len(АЛФАВИТЫ["ru"])+2),"В")
    def test_caesar_punctuation(self): self.assertEqual(зашифровать_цезарем("А, Б!",1),"Б, В!")
    def test_atbash_twice(self): self.assertEqual(атбаш(атбаш("ПРИВЕТ")),"ПРИВЕТ")
    def test_polybius_encode_decode(self):
        table=построить_полибия("АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",6)
        self.assertEqual(полибия_декодировать(полибия_кодировать("АБВ",table),table),"АБВ")
    def test_polybius_unknown(self):
        table=построить_полибия("АБВГДЕ",3)
        with self.assertRaises(ValueError): полибия_кодировать("Ж",table)
    def test_vigenere_roundtrip(self): self.assertEqual(из_виженера(в_виженера("АТАКА","КЛЮЧ"),"КЛЮЧ"),"АТАКА")
    def test_vigenere_empty_key(self):
        with self.assertRaises(ValueError): в_виженера("ТЕКСТ","")
    def test_vigenere_repeated_letters(self): self.assertNotEqual(в_виженера("АААА","БА"),"АААА")
    def test_permutation_roundtrip(self): self.assertEqual(обратная_перестановка(перестановка_блоков("ABCD",[2,0,3,1]),[2,0,3,1]),"ABCD")
    def test_permutation_invalid(self):
        with self.assertRaises(ValueError): перестановка_блоков("AB",[0,0])
    def test_frequency_count(self): self.assertEqual(частоты("ААБ","АБ")["количество"],3)
    def test_caesar_bruteforce_size(self): self.assertEqual(len(перебор_цезаря("ТЕСТ",АЛФАВИТЫ["ru"])),len(АЛФАВИТЫ["ru"]))
    def test_lsb_roundtrip(self):
        pixels=[100]*500
        self.assertEqual(извлечь_lsb(встроить_lsb(pixels,"OK")),"OK")
    def test_lsb_capacity(self):
        with self.assertRaises(ValueError): встроить_lsb([1]*10,"long")
    def test_lsb_modified_detect(self):
        carrier=встроить_lsb([100]*500,"OK"); carrier[40]^=1
        self.assertTrue(повреждение_обнаружено(carrier,"OK"))
    def test_sha_hash(self): self.assertEqual(len(вычислить_хеш("data")),64)
    def test_sha_integrity_ok(self):
        h=вычислить_хеш("data"); self.assertTrue(проверить_целостность("data",h))
    def test_sha_integrity_changed(self): self.assertFalse(проверить_целостность("changed",вычислить_хеш("data")))
    def test_aes_gcm_roundtrip(self):
        k=создать_ключ_aes(); e=aes_зашифровать("hello",k); self.assertEqual(aes_расшифровать(e["ciphertext"],e["nonce"],k).decode(),"hello")
    def test_aes_gcm_tamper(self):
        k=создать_ключ_aes(); e=aes_зашифровать("hello",k); damaged=e["ciphertext"][:-1]+bytes([e["ciphertext"][-1]^1])
        with self.assertRaises(Exception): aes_расшифровать(damaged,e["nonce"],k)
    def test_signature_valid(self):
        priv,pub=создать_пару_rsa(); sig=подписать_документ("doc",priv); self.assertEqual(проверить_подпись("doc",sig,pub),"действительна")
    def test_signature_changed_doc(self):
        priv,pub=создать_пару_rsa(); sig=подписать_документ("doc",priv); self.assertEqual(проверить_подпись("doc2",sig,pub),"недействительна")
    def test_signature_wrong_key(self):
        p1,u1=создать_пару_rsa(); p2,u2=создать_пару_rsa(); sig=подписать_документ("doc",p1); self.assertEqual(проверить_подпись("doc",sig,u2),"недействительна")
    def test_tls_reject_invalid_cert(self): self.assertEqual(учебный_tls_сеанс(False)["статус"],"отказ")
    def test_tls_flag_high_volume(self): self.assertEqual(метка_сетевого_события({"объём":900000,"новый_процесс":False}),"требует анализа")
def метка_сетевого_события(event):
    if event.get("объём",0)>500000 or event.get("новый_процесс") or event.get("повтор",0)>8:
        return "требует анализа"
    return "обычное"
