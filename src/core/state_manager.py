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
