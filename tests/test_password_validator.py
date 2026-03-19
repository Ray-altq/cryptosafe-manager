import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.crypto.password_validator import PasswordValidator

class TestPasswordValidator(unittest.TestCase):  #класс для тестирования функциональности проверки паролей
    
    def setUp(self):  #метод для настройки тестовой среды
        self.validator = PasswordValidator()
    
    def test_min_length(self):  #тест для проверки минимальной длины пароля
        is_valid, errors = self.validator.validate("Short1!", strict=False)
        self.assertFalse(is_valid)
        self.assertTrue(any("минимум 12 символов" in err for err in errors))
        
        is_valid, errors = self.validator.validate("ValidLongPassword123!", strict=False)
        self.assertTrue(is_valid)
    
    def test_uppercase_required(self):  #тест для проверки наличия заглавной буквы
        is_valid, errors = self.validator.validate("nouppercase123!", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("заглавную букву" in err for err in errors))
        
        is_valid, errors = self.validator.validate("HasUppercase123!", strict=True)
        self.assertTrue(is_valid)
    
    def test_lowercase_required(self):  #тест для проверки наличия строчной буквы
        is_valid, errors = self.validator.validate("NOLOWERCASE123!", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("строчную букву" in err for err in errors))
        
        is_valid, errors = self.validator.validate("HasLowercase123!", strict=True)
        self.assertTrue(is_valid)
    
    def test_digits_required(self):  #тест для проверки наличия цифры
        is_valid, errors = self.validator.validate("NoDigitsHere!", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("цифру" in err for err in errors))
        
        is_valid, errors = self.validator.validate("HasDigits123!", strict=True)
        self.assertTrue(is_valid)
    
    def test_special_chars_required(self):  #тест для проверки наличия специального символа
        is_valid, errors = self.validator.validate("NoSpecial123", strict=True)
        self.assertFalse(is_valid)
        self.assertTrue(any("специальный символ" in err for err in errors))
        
        is_valid, errors = self.validator.validate("HasSpecial123!", strict=True)
        self.assertTrue(is_valid)
    
    def test_common_passwords(self):  #тест для проверки отклонения распространенных паролей
        common = ["password", "123456", "qwerty", "admin", "letmein"]
        for pwd in common:
            test_pwd = pwd + "A1!"
            is_valid, errors = self.validator.validate(test_pwd, strict=True)
            self.assertFalse(is_valid, f"Пароль {pwd} должен быть отклонен")
            self.assertTrue(any("распространен" in err for err in errors), 
                          f"Ошибка для {pwd}: {errors}")
    
    def test_sequences(self):  #тест для проверки отклонения паролей с простыми последовательностями
        sequences = ["123", "abc", "qwerty", "asdf", "12345"]
        for seq in sequences:
            pwd = seq + "A1!"  #добавляем, чтобы пройти другие проверки
            is_valid, errors = self.validator.validate(pwd, strict=True)
            self.assertFalse(is_valid, f"Пароль с {seq} должен быть отклонен")
    
    def test_repetitions(self):  #тест для проверки отклонения паролей с повторяющимися символами
        #4 одинаковых подряд
        is_valid, errors = self.validator.validate("aaaaA1!", strict=True)
        self.assertFalse(is_valid)
        
        #много одинаковых в разных местах - должно быть ок
        is_valid, errors = self.validator.validate("Aa1!Aa1!Aa1!Aa1!", strict=True)
        self.assertTrue(is_valid)
    
    def test_valid_password(self):  #тест для проверки, что хороший пароль проходит все проверки
        good_passwords = [
            "Tr0ub4dor&3",           
            "CorrectHorseBatteryStaple!",  
            "P@ssw0rdWithGoodLength1!",
            "MySecureP@ssw0rd2024!"
        ]
        
        for pwd in good_passwords:
            is_valid, errors = self.validator.validate(pwd, strict=True)
            self.assertTrue(is_valid, f"Пароль {pwd} должен быть валидным, ошибки: {errors}")
    
    def test_strength_score(self):  #тест для проверки оценки силы пароля
        validator = PasswordValidator()
        
        score1 = validator.get_strength_score("123")
        self.assertLess(score1, 20)
       
        score2 = validator.get_strength_score("Password123")
        self.assertGreaterEqual(score2, 40)
        self.assertLess(score2, 80)
        
        score3 = validator.get_strength_score("Tr0ub4dor&3")
        self.assertGreaterEqual(score3, 70) 
    
    def test_strength_labels(self):  #тест для проверки правильности меток силы пароля
        validator = PasswordValidator()
        self.assertEqual(validator.get_strength_label(10), "Очень слабый")
        self.assertEqual(validator.get_strength_label(30), "Слабый")
        self.assertEqual(validator.get_strength_label(50), "Средний")
        self.assertEqual(validator.get_strength_label(70), "Хороший")
        self.assertEqual(validator.get_strength_label(90), "Отличный")
    
    def test_suggestions(self):  #тест для проверки генерации рекомендаций по улучшению пароля
        validator = PasswordValidator()
        weak_pwd = "123"
        suggestions = validator.suggest_improvements(weak_pwd)
        
        self.assertGreater(len(suggestions), 0)
        #проверяем наличие разных типов рекомендаций
        suggestion_text = " ".join(suggestions).lower()
        self.assertTrue("длин" in suggestion_text or "символ" in suggestion_text)

if __name__ == '__main__':
    unittest.main()