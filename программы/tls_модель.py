import secrets
def учебный_tls_сеанс(server_certificate_valid=True, message="TEST MESSAGE"):
    if not server_certificate_valid:
        return {"статус":"отказ","этап":"проверка сертификата","сообщение":"Сведения о сервере не прошли учебную проверку."}
    shared_secret=secrets.token_bytes(32)
    session_key=shared_secret  # упрощённая учебная модель; не TLS
    return {"статус":"условно установлен","этапы":["проверка сертификата","условное согласование секрета","получение ключа сеанса","обмен тестовым сообщением"],"сообщение":message,"длина_ключа":len(session_key),"примечание":"Не является реализацией TLS."}
