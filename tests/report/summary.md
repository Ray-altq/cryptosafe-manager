# Отчет по тестированию

Дата формирования: 2026-05-30

## Основной набор тестов

Команда:

```powershell
python -m pytest
```

Результат:

- 363 теста пройдено
- 10 медленных stress/performance тестов исключены из основного запуска
- Время выполнения: 20.78с

## Проверка покрытия

Команда:

```powershell
python -m pytest --cov=src --cov-report=term --cov-report=html:tests/report/html --junitxml=tests/report/junit.xml
```

Результат:

- 363 теста пройдено
- 10 медленных stress/performance тестов исключены из coverage-запуска
- Общее покрытие: 84%
- HTML-отчет: `tests/report/html/index.html`
- JUnit-отчет: `tests/report/junit.xml`

Из процента покрытия исключен каталог `src/gui/*`

## Медленные stress-проверки

Команда:

```powershell
python -m pytest -m slow
```

Результат:

- 10 тестов пройдено
- 363 обычных теста исключены из slow-запуска
- Время выполнения: 36.32с
