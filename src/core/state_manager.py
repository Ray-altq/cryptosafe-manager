from datetime import datetime, timedelta
from typing import Optional
from enum import Enum

class SessionState(Enum):  #состояние сессии пользователя
    LOCKED = "locked"
    UNLOCKED = "unlocked"
