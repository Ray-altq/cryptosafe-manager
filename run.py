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
    print("\nУбедитесь, что файл существует:")
    print("  src/gui/main_window.py")
    sys.exit(1)

if __name__ == "__main__":
    print("=" * 50)
    print("CryptoSafe Manager")
    print("=" * 50)
    
    try:
        app = MainWindow()
        app.run()
    except Exception as e:
        print(f"\nОшибка: {e}")
        import traceback
        traceback.print_exc()
        input("\nНажмите Enter для выхода...")