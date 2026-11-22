from collections import Counter
from программы.классические_шифры import расшифровать_цезарем
from программы.нормализация import нормализовать_текст

def перебор_цезаря(шифротекст, алфавит):
    return [{"ключ":k,"текст":расшифровать_цезарем(шифротекст,k,алфавит),"оценка":0} for k in range(len(алфавит))]

def частоты(текст,алфавит):
    filtered=[c.upper() for c in текст if c.upper() in алфавит]
    count=Counter(filtered); total=len(filtered)
    return {"количество":total,"частоты":dict(count),"доли":{c:round(v/total,4) for c,v in count.items()} if total else {},"по_убыванию":count.most_common()}

def оценить_русский_текст(text):
    # Простая эвристика, не полноценный языковой анализ.
    words={"И","В","НА","С","ПО","К","У","О","А","НЕ","ЭТО","ДЛЯ","ЧТО"}
    return sum(w in words for w in text.upper().split())
