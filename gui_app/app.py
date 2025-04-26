import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..rsa import (
    generate_keypair, 
    save_key_to_file, 
    encrypt_file, 
    decrypt_file
)

class RSA_OAEP_App:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP Encryption/Decryption Tool")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create frames for each tab
        self.keygen_frame = ttk.Frame(self.notebook, padding="10")
        self.encrypt_frame = ttk.Frame(self.notebook, padding="10")
        self.decrypt_frame = ttk.Frame(self.notebook, padding="10")
        
        # Add tabs to notebook
        self.notebook.add(self.keygen_frame, text="Key Generation")
        self.notebook.add(self.encrypt_frame, text="Encryption")
        self.notebook.add(self.decrypt_frame, text="Decryption")
        
        # Set up each tab
        self.setup_keygen_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))
    
    def setup_keygen_tab(self):
        # Key size options
        ttk.Label(self.keygen_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.key_size_var = tk.StringVar(value="2048")
        key_size_combo = ttk.Combobox(self.keygen_frame, textvariable=self.key_size_var, state="readonly")
        key_size_combo['values'] = ('1024', '2048', '3072', '4096')
        key_size_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Output directory
        ttk.Label(self.keygen_frame, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.output_dir_var = tk.StringVar()
        ttk.Entry(self.keygen_frame, textvariable=self.output_dir_var, width=50).grid(