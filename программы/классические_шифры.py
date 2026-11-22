from программы.нормализация import нормализовать_текст
from данные.параметры_алгоритмов import АЛФАВИТЫ

def _caesar(text, shift, alphabet):
    if not isinstance(shift, int): raise ValueError("Сдвиг должен быть целым числом.")
    if not alphabet: raise ValueError("Алфавит не задан.")
    n=len(alphabet); shift=shift % n
    out=[]
    for ch in text:
        upper=ch.upper()
        if upper in alphabet:
            new=alphabet[(alphabet.index(upper)+shift)%n]
            out.append(new if ch.isupper() else new.lower())
        else: out.append(ch)
    return "".join(out)

def зашифровать_цезарем(текст, сдвиг, алфавит=АЛФАВИТЫ["ru"]):
    return _caesar(текст, сдвиг, алфавит)
def расшифровать_цезарем(текст, сдвиг, алфавит=АЛФАВИТЫ["ru"]):
    return _caesar(текст, -сдвиг, алфавит)

def атбаш(текст, алфавит=АЛФАВИТЫ["ru"]):
    reverse=алфавит[::-1]; result=[]
    for ch in текст:
        u=ch.upper()
        if u in алфавит:
            c=reverse[алфавит.index(u)]
            result.append(c if ch.isupper() else c.lower())
        else: result.append(ch)
    return "".join(result)

def построить_полибия(алфавит, размер=5):
    unique=[]
    for ch in алфавит:
        if ch not in unique: unique.append(ch)
    return [unique[i:i+размер] for i in range(0,len(unique),размер)]

def полибия_кодировать(текст, таблица):
    coords={ch:(r+1,c+1) for r,row in enumerate(таблица) for c,ch in enumerate(row)}
    output=[]
    for ch in текст.upper():
        if ch in coords: output.append("".join(map(str,coords[ch])))
        elif ch.isalpha(): raise ValueError(f"Символ {ch!r} отсутствует в квадрате Полибия.")
        else: output.append(ch)
    return " ".join(output)

def полибия_декодировать(код, таблица):
    output=[]
    for token in код.split():
        if token.isdigit() and len(token)==2:
            r,c=int(token[0])-1,int(token[1])-1
            if r<0 or c<0 or r>=len(таблица) or c>=len(таблица[r]): raise ValueError("Координаты вне таблицы.")
            output.append(таблица[r][c])
        else: output.append(token)
    return "".join(output)

def _vigenere(text,key,alphabet,sign):
    if not isinstance(key,str) or not key: raise ValueError("Ключ Виженера не должен быть пустым.")
    key_chars=[c.upper() for c in key if c.upper() in alphabet]
    if not key_chars: raise ValueError("Ключ не содержит символов выбранного алфавита.")
    out=[]; j=0
    for ch in text:
        u=ch.upper()
        if u in alphabet:
            shift=alphabet.index(key_chars[j%len(key_chars)])
            new=alphabet[(alphabet.index(u)+sign*shift)%len(alphabet)]
            out.append(new if ch.isupper() else new.lower()); j+=1
        else: out.append(ch)
    return "".join(out)
def в_виженера(text,key,alphabet=АЛФАВИТЫ["ru"]): return _vigenere(text,key,alphabet,1)
def из_виженера(text,key,alphabet=АЛФАВИТЫ["ru"]): return _vigenere(text,key,alphabet,-1)

def перестановка_блоков(text, indices):
    if sorted(indices)!=list(range(len(indices))): raise ValueError("Ключ перестановки должен быть перестановкой индексов 0..n-1.")
    return "".join(text[i] for i in indices)
def обратная_перестановка(text,indices):
    if len(text)!=len(indices) or sorted(indices)!=list(range(len(indices))): raise ValueError("Некорректная перестановка или длина.")
    result=[""]*len(indices)
    for out_pos,source_pos in enumerate(indices): result[source_pos]=text[out_pos]
    return "".join(result)

def кардано_записать(text,size,holes):
    if size<1 or size%2: raise ValueError("Размер учебной решётки должен быть чётным.")
    mask=set(holes); rotated=set()
    for r,c in holes:
        if not(0<=r<size and 0<=c<size): raise ValueError("Отверстие вне матрицы.")
        for _ in range(4):
            rotated.add((r,c)); r,c=c,size-1-r
    if len(rotated)!=size*size: raise ValueError("Маска и повороты не покрывают матрицу без пересечений.")
    chars=list(text[:size*size].ljust(size*size,"·")); grid=[[""]*size for _ in range(size)]
    idx=0
    for _ in range(4):
        for r,c in sorted(mask):
            grid[r][c]=chars[idx]; idx+=1
        mask={(c,size-1-r) for r,c in mask}
    return grid

def кардано_прочитать(grid,holes):
    size=len(grid); mask=set(holes); output=[]
    for _ in range(4):
        for r,c in sorted(mask): output.append(grid[r][c])
        mask={(c,size-1-r) for r,c in mask}
    return "".join(output).replace("·","").rstrip()
