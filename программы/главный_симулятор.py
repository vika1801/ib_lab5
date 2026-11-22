import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from данные.сообщения import СООБЩЕНИЯ
from данные.параметры_алгоритмов import АЛФАВИТЫ
from программы.классические_шифры import *
from программы.криптоанализ import *
from программы.стеганография import *
from программы.современные_примитивы import *
from программы.электронная_подпись import *
from программы.tls_модель import учебный_tls_сеанс
from программы.тестирование import метка_сетевого_события
import unittest

def report(name,content):
    path=ROOT/"отчёты"/name
    path.write_text(content,encoding="utf-8")
    print(f"Сохранено: {path.relative_to(ROOT)}")

def classic():
    msg="ВСТРЕЧА УЧЕБНОЙ ГРУППЫ В ДЕСЯТЬ ЧАСОВ"
    encrypted=зашифровать_цезарем(msg,3)
    decrypted=расшифровать_цезарем(encrypted,3)
    atbash=атбаш("ПРИВЕТ")
    v=в_виженера("АТАКА В ПЯТЬ ЧАСОВ","КЛЮЧ")
    report("отчёт_классические_шифры.txt",f"Цезарь\nОткрытый текст: {msg}\nСдвиг: 3\nШифротекст: {encrypted}\nРасшифрование: {decrypted}\nАтбаш: ПРИВЕТ -> {atbash}\nВиженер: АТАКА В ПЯТЬ ЧАСОВ -> {v}\n")
    print("Цезарь:",encrypted,"=>",decrypted); print("Атбаш:",atbash); print("Виженер:",v)

def analysis():
    cipher=зашифровать_цезарем("ЭТО УЧЕБНЫЙ ТЕКСТ",5)
    rows=перебор_цезаря(cipher,АЛФАВИТЫ["ru"])
    freqs=частоты("ЭТО УЧЕБНЫЙ ТЕКСТ И ЕЩЁ ОДНО ПРЕДЛОЖЕНИЕ",АЛФАВИТЫ["ru"])
    report("отчёт_криптоанализа.txt","Перебор Цезаря:\n"+"\n".join(f"{r['ключ']}: {r['текст']}" for r in rows)+"\nЧастоты открытого текста: "+str(freqs)+"\nВывод: короткий текст не позволяет уверенно определить ключ.")
    print("Перебор ключей:",len(rows),"вариантов; отчет записан.")

def stego():
    text="учебное сообщение"
    carrier=[128]*500
    hidden=встроить_lsb(carrier,text)
    decoded=извлечь_lsb(hidden)
    damaged=hidden.copy(); damaged[40]^=1
    report("отчёт_стеганография.txt",f"Сообщение: {text}\nИзвлечено: {decoded}\nИзменение элемента обнаружено: {повреждение_обнаружено(damaged,text)}\nLSB скрывает факт наличия текста лишь условно; криптографической защиты не дает.")
    print("LSB извлечение:",decoded)

def hash_aes():
    document="Учебный документ для проверки."
    h=вычислить_хеш(document); changed=проверить_целостность(document+"!",h)
    key=создать_ключ_aes(); encrypted=aes_зашифровать(document,key)
    decrypted=aes_расшифровать(encrypted["ciphertext"],encrypted["nonce"],key).decode()
    damaged=encrypted["ciphertext"][:-1]+bytes([encrypted["ciphertext"][-1]^1])
    try: aes_расшифровать(damaged,encrypted["nonce"],key); tamper="ошибка не выявлена"
    except Exception: tamper="повреждение выявлено, текст не выдан"
    report("отчёт_целостность_и_подпись.txt",f"SHA-256: {h}\nИзмененный документ проходит проверку: {changed}\nAES-GCM: исходный текст восстановлен: {decrypted==document}\nТампер-тест AES-GCM: {tamper}\n")
    print("Хеш:",h,"AES-GCM tamper:",tamper)

def signature():
    doc="Условный документ CryptoLab."
    private,public=создать_пару_rsa(); sig=подписать_документ(doc,private)
    valid=проверить_подпись(doc,sig,public); changed=проверить_подпись(doc+" изменен",sig,public)
    _,other=создать_пару_rsa(); wrong=проверить_подпись(doc,sig,other)
    report("отчёт_целостность_и_подпись.txt",f"Подпись исходного: {valid}\nПодпись измененного документа: {changed}\nПроверка другим ключом: {wrong}\nЗакрытый ключ не сохранялся.")
    print("Подпись:",valid,"измененный документ:",changed,"чужой ключ:",wrong)

def tls():
    print(учебный_tls_сеанс())
    events=[{"время":f"2026-01-01 00:{i:02d}","адрес":"192.0.2.10","протокол":"HTTPS","объём":10000+i*30000,"процесс":"browser.exe","новый_процесс":i==18,"повтор":i} for i in range(20)]
    flagged=[e for e in events if метка_сетевого_события({"объём":e["объём"],"новый_процесс":e["новый_процесс"],"повтор":e["повтор"]})!="обычное"]
    report("анализ_сетевого_журнала.txt","Учебных событий: 20\nСобытия, требующие анализа: "+str(flagged)+"\nTLS/HTTPS не означает автоматическую атаку.")
    print("Событий в журнале:",len(events),"требуют внимания:",len(flagged))

def incidents():
    data=[
    ("WannaCry","2017","массовое ransomware; шифрование файлов","глобальная вспышка; ущерб зависит от источника и масштаба"),
    ("NotPetya","2017","деструктивная атака, маскировалась под ransomware","нарушение бизнес-процессов и инфраструктуры"),
    ("Colonial Pipeline","2021","ransomware-инцидент; остановка части операций","влияние на топливные поставки в США")]
    report("анализ_инцидентов.txt","\n".join(" | ".join(row) for row in data)+"\nМеры: резервные копии, обновления, сегментация, MFA, мониторинг, план реагирования. Численные оценки здесь не приводятся, поскольку требуют конкретного источника и масштаба.")
    print("Сравнительный файл инцидентов сформирован (численные оценки ущерба не выдумывались).")

def run_tests():
    suite=unittest.defaultTestLoader.discover(str(ROOT/"tests"))
    # Тестовый модуль импортируется из папки tests.
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report("результаты_тестов.txt",f"Всего: {result.testsRun}\nОшибок: {len(result.errors)}\nПровалов: {len(result.failures)}\n")
    return result.wasSuccessful()

def all_modules():
    classic(); analysis(); stego(); hash_aes(); signature(); tls(); incidents(); run_tests()
    report("итоговый_отчёт.txt","CryptoLab выполнен. Сформированы отчеты по классическим шифрам, анализу, LSB, хешу/AES-GCM, подписи, TLS-модели, инцидентам и тестам. Все демонстрации учебные.")
def menu():
    commands={"все":all_modules,"классика":classic,"анализ":analysis,"стего":stego,"хеш":hash_aes,"подпись":signature,"tls":tls,"инциденты":incidents,"тесты":run_tests}
    print("CryptoLab — учебный симулятор")
    print("Команды:",", ".join(commands),"выход")
    while True:
        try: cmd=input("> ").strip().lower()
        except EOFError: break
        if cmd in ("выход","exit","quit"): break
        if cmd in commands:
            try: commands[cmd]()
            except Exception as exc: print("Контролируемая ошибка:",exc)
        else: print("Неизвестная команда. Введите одну из:",", ".join(commands),"выход")
if __name__=="__main__": menu()
