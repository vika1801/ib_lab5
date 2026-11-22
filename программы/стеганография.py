def текст_в_биты(text):
    data=text.encode("utf-8")
    bits="".join(f"{byte:08b}" for byte in data)
    return f"{len(data):032b}"+bits  # первые 32 бита — длина в байтах

def встроить_lsb(pixels,text):
    bits=текст_в_биты(text)
    if len(bits)>len(pixels): raise ValueError("Недостаточная вместимость LSB-носителя.")
    result=list(pixels)
    for i,bit in enumerate(bits): result[i]=(result[i]&254)|int(bit)
    return result

def извлечь_lsb(pixels):
    bits="".join(str(p&1) for p in pixels)
    if len(bits)<32: raise ValueError("Носитель слишком короткий.")
    length=int(bits[:32],2); needed=32+length*8
    if needed>len(bits): raise ValueError("Носитель повреждён или длина сообщения некорректна.")
    data=bytes(int(bits[i:i+8],2) for i in range(32,needed,8))
    return data.decode("utf-8")

def повреждение_обнаружено(pixels,expected):
    try: return извлечь_lsb(pixels)!=expected
    except (ValueError,UnicodeDecodeError): return True
