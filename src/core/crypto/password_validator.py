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
    
    def _has_sequences(self, password: str) -> bool:
        password_lower = password.lower()
        
        #распространенные последовательности
        sequences = [
            '123', '234', '345', '456', '567', '678', '789',
            'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi',
            'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio',
            'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl',
            'zxc', 'xcv', 'cvb', 'vbn', 'bnm',
            'qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl'
        ]
        
        for seq in sequences:
            if seq in password_lower:
                return True
        
        #проверка на клавиатурные ряды (qwerty, йцукен)
        keyboard_rows = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            'йцукенгшщзхъ', 'фывапролджэ', 'ячсмитьбю'
        ]
        
        for row in keyboard_rows:
            for i in range(len(row) - 3):
                seq = row[i:i+4]
                if seq in password_lower:
                    return True
        
        return False
    
    def _has_repetitions(self, password: str) -> bool:
        if re.search(r'(.)\1{3,}', password):  #проверка на 4+ одинаковых символа подряд
            return True
        
        from collections import Counter
        counts = Counter(password.lower())  #проверка на 8+ одинаковых символов в любом месте
        for char, count in counts.items():
            if count > 7 and char.isalnum():
                return True
        
        return False
    
    def get_strength_score(self, password: str) -> int:
        score = 0
        
        length_score = min(40, len(password) * 2)
        score += length_score
        
        #разнообразие символов
        has_upper = 1 if re.search(r'[A-Z]', password) else 0
        has_lower = 1 if re.search(r'[a-z]', password) else 0
        has_digit = 1 if re.search(r'\d', password) else 0
        has_special = 1 if re.search(r'[!@#$%^&*(),.?":{}|<>]', password) else 0
        
        variety = (has_upper + has_lower + has_digit + has_special) * 7.5
        score += variety
        
        #штрафы
        #штраф за распространенный пароль
        if password.lower() in self.common_passwords:
            score -= 30
        
        #штраф за последовательности
        if self._has_sequences(password):
            score -= 15
        
        #штраф за повторения
        if self._has_repetitions(password):
            score -= 15
        
        #ограничиваем диапазон 0-100
        return max(0, min(100, int(score)))
    
    def get_strength_label(self, score: int) -> str:
        if score < 20:
            return "Очень слабый"
        elif score < 40:
            return "Слабый"
        elif score < 60:
            return "Средний"
        elif score < 80:
            return "Хороший"
        else:
            return "Отличный"
    
    def suggest_improvements(self, password: str) -> List[str]:  #рекомендации
        suggestions = []
        
        if len(password) < self.min_length:
            suggestions.append(f"Увеличьте длину до {self.min_length}+ символов")
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            suggestions.append("Добавьте заглавные буквы")
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            suggestions.append("Добавьте строчные буквы")
        
        if self.require_digits and not re.search(r'\d', password):
            suggestions.append("Добавьте цифры")
        
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            suggestions.append("Добавьте специальные символы")
        
        if self._has_sequences(password):
            suggestions.append("Избегайте простых последовательностей (123, abc, qwerty)")
        
        if self._has_repetitions(password):
            suggestions.append("Избегайте повторяющихся символов")
        
        if password.lower() in self.common_passwords:
            suggestions.append("Этот пароль слишком распространен")
        
        return suggestions