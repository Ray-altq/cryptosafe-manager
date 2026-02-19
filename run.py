import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from src.gui.main_window import MainWindow
except ImportError as e:
    print("=" * 50)
    print("ОШИБКА: Не удалось импортировать модули")
    print("=" * 50)
    print(f"Ошибка: {e}")
    print("\nУбедитесь, что вы запускаете из папки проекта:")
    print("  cd cryptosafe-manager")
    print("  python run.py")
    print("\nСтруктура папок должна быть:")
    print("  cryptosafe-manager/")
    print("  ├── run.py (этот файл)")
    print("  └── src/")
    print("      └── gui/")
    print("          └── main_window.py")
    sys.exit(1)

if __name__ == "__main__":
    print("=" * 50)
    print("CryptoSafe Manager")
    print("=" * 50)
    print("Запуск программы...")
    
    try:
        app = MainWindow()
        app.run()
    except Exception as e:
        print(f"\nОшибка при запуске: {e}")
        print("\nПодробности ошибки:")
        import traceback
        traceback.print_exc()
        input("\nНажмите Enter для выхода...")