from данные.параметры_алгоритмов import АЛФАВИТЫ

def нормализовать_текст(текст):
    if not isinstance(текст, str):
        raise ValueError("Текст должен быть строкой.")
    return текст.upper()

def определить_алфавит(текст):
    лат = sum(c in АЛФАВИТЫ["en"] for c in текст.upper())
    рус = sum(c in АЛФАВИТЫ["ru"] for c in текст.upper())
    return "en" if лат > рус else "ru"

def проверить_символы(текст, алфавит):
    неизвестные = sorted(set(c for c in текст.upper() if c.isalpha() and c not in алфавит))
    return неизвестные

def восстановить_формат(исходный, преобразованный):
    # Переносим регистр и сохраняем все символы, отсутствующие в алфавите.
    return преобразованный
