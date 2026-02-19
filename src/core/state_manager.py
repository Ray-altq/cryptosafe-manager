from datetime import datetime, timedelta
from typing import Optional
from enum import Enum

class SessionState(Enum):  #состояние сессии пользователя
    LOCKED = "locked"
    UNLOCKED = "unlocked"

class StateManager:  #управление состоянием
    def __init__(self):
        self.session_state = SessionState.LOCKED  #текущее состояние (по умолчанию заблокировано)
        self.last_activity: Optional[datetime] = None  #время последней активности
        #буфер обмена и его таймер
        self.clipboard_content: Optional[str] = None
        self.clipboard_timer: Optional[datetime] = None
        #таймаут неактивности (будет браться из config)
        self.inactivity_timeout: int = 300  #5 минут

    def unlock(self):  #разблок
        self.session_state = SessionState.UNLOCKED
        self.update_activity()
    
    def lock(self):  #блок
        self.session_state = SessionState.LOCKED
        #при блокировке очищаем буфер обмена
        self.clipboard_content = None
        self.clipboard_timer = None
    
    def is_locked(self) -> bool:  #проверка, заблокировано ли приложение
        return self.session_state == SessionState.LOCKED
    
    def is_unlocked(self) -> bool:  #проверка, разблокировано ли приложение
        return self.session_state == SessionState.UNLOCKED
    
    def update_activity(self):  #обновление времени последней активности
        self.last_activity = datetime.now()
    
    def get_idle_time(self) -> float:  #сколько секунд прошло с последней активности
        if self.last_activity is None:
            return 0
        return (datetime.now() - self.last_activity).total_seconds()
    
    def should_auto_lock(self) -> bool:  #проверка на автоблокировку
        if self.session_state != SessionState.UNLOCKED:
            return False
        if self.last_activity is None:
            return False
        
        return self.get_idle_time() >= self.inactivity_timeout
    
    def set_inactivity_timeout(self, seconds: int):  #установка таймаута неактивности (берем из кфг)
        self.inactivity_timeout = seconds

    def set_clipboard(self, content: str, timeout_seconds: int = 30):  #установка содержимого буфера обмена с таймером
        self.clipboard_content = content
        if timeout_seconds > 0:
            self.clipboard_timer = datetime.now() + timedelta(seconds=timeout_seconds)
    
    def get_clipboard(self) -> Optional[str]:  #получение содержимого буфера (с проверкой таймера)
        #проверяем, не истек ли таймер
        if self.clipboard_timer and datetime.now() >= self.clipboard_timer:
            self.clipboard_content = None
            self.clipboard_timer = None
        
        return self.clipboard_content
    
    def clear_clipboard(self):  #принудительная очистка буфера
        self.clipboard_content = None
        self.clipboard_timer = None
    
    
