import json  #для работы с JSON файлами (чтение/запись)
import os    #для работы с операционной системой (пути, папки)
from pathlib import Path  #удобная работа с путями файлов (современный способ)
from typing import Any, Dict  #для подсказок типов (Any - любой тип, Dict - словарь)

class Config:
    #этот класс будет хранить все настройки программы и сохранять их в файл (кфг как в кс)
    
    #значения по дефолту (если нет файла конфигурации)
    DEFAULTS = {
        #настройки базы данных
        'database': {
            'path': str(Path.home() / '.cryptosafe' / 'vault.db'),  #путь к файлу БД в домашней папке пользователя
        },
        #настройки безопасности
        'security': {
            'clipboard_timeout': 30,  #через сколько секунд очищать буфер обмена
            'auto_lock_minutes': 5,    #через сколько минут бездействия блокировать приложение
        },
        #настройки внешнего вида
        'appearance': {
            'theme': 'default',  #тема оформления (default/dark/light)
            'language': 'en',    #язык интерфейса (en/ru)
        }
    }

    def __init__(self):  #конструктор, который создает объект конфига
        self.config = self.DEFAULTS.copy()
        self.config_file = Path.home() / '.cryptosafe' / 'config.json'
        self._ensure_config_dir()
        self._load()
    
    def _ensure_config_dir(self):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)  #создает папку конфига, если ее нет
    