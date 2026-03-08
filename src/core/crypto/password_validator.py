import re
import secrets
from typing import List, Tuple, Optional

class PasswordValidator:
    def __init__(self, config: dict = None):
        if config is None:
            config = {}
        
        self.min_length = config.get('min_password_length', 12)  #минимальная длина пароля (минимум 12 символов)
        
        #требования к символам
        self.require_uppercase = config.get('require_uppercase', True)      #заглавные
        self.require_lowercase = config.get('require_lowercase', True)      #строчные
        self.require_digits = config.get('require_digits', True)            #цифры
        self.require_special = config.get('require_special', True)          #спецсимволы
        
        #список распространенных паролей
        self.common_passwords = [
            'password12345', '1234567890qq', 'qwerty', 'password123', 'admin',
            'zxcqwe', 'welcome', 'monkey', 'dragon', 'master',
            'demon228', 'lolkek', '', 'qazwsx', 'pudge1337'
        ]
    
    def validate(self, password: str) -> Tuple[bool, List[str]]:
        errors = []
        
        if len(password) < self.min_length:  #проверка длины
            errors.append(f"Пароль должен содержать минимум {self.min_length} символов")
        
        if not password:  #проверка на пустой пароль
            errors.append("Пароль не может быть пустым")
            return False, errors
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):  #проверка наличия заглавных букв
            errors.append("Пароль должен содержать хотя бы одну заглавную букву")
        
        if self.require_lowercase and not re.search(r'[a-z]', password):  #проверка наличия строчных букв
            errors.append("Пароль должен содержать хотя бы одну строчную букву")
        
        if self.require_digits and not re.search(r'\d', password):  #проверка наличия цифр
            errors.append("Пароль должен содержать хотя бы одну цифру")
        
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  #проверка наличия спецсимволов
            errors.append("Пароль должен содержать хотя бы один специальный символ")
        
        if password.lower() in self.common_passwords:  #проверка на распространенные пароли
            errors.append("Этот пароль слишком распространен")
        
        if self._has_sequences(password):  #проверка на последовательности (123, abc, qwerty)
            errors.append("Пароль содержит простую последовательность (например, 123 или abc)")
        
        if self._has_repetitions(password):  #проверка на повторяющиеся символы
            errors.append("Пароль содержит слишком много повторяющихся символов")
        
        return len(errors) == 0, errors