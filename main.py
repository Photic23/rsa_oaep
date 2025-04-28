import tkinter as tk
from gui_app import RSA_OAEP_App

def main():
    """Main entry point for the application"""    
    # Start the GUI application
    root = tk.Tk()
    app = RSA_OAEP_App(root)
    root.mainloop()

if __name__ == "__main__":
    main()