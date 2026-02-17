import secrets
from typing import Optional, Tuple

class KeyManager:   #менеджер для работы с ключами шифрования
    
    def __init__(self):
        self.current_key = None   #при создании у менеджера нет текущего ключа
    
    def derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]: #делаем из пароля ключ шифрования
        if salt is None:  #если соли нет - создаем новую
            salt = secrets.token_bytes(16)
        
        password_bytes = password.encode('utf-8')  #записываем пароль в байты
        
        key = password_bytes + salt  #смешиваем пароль с солью
        
        #обрезаем до 32 байт, тк для AES-256(симметричный блочный алгоритм шифрования) нужно 32 байта
        if len(key) > 32:
            key = key[:32]
        elif len(key) < 32:
            #если слишком короткий - дополним нулями
            key = key + b'\x00' * (32 - len(key))
        
        return key, salt
    
    def store_key(self, key_id: str, key: bytes):
        self.current_key = key
        print(f"Ключ {key_id} сохранен")  #сохраняем ключ(пока в память, потом в БД)
    
    def load_key(self, key_id: str) -> Optional[bytes]:  #загружаем ключ(пока из памяти, далее из БД)
        
        return self.current_key