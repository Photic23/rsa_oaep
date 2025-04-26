import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import traceback

from rsa import (
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
        key_size_combo['values'] = ('2048')
        key_size_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Output directory
        ttk.Label(self.keygen_frame, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.output_dir_var = tk.StringVar()
        ttk.Entry(self.keygen_frame, textvariable=self.output_dir_var, width=50).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.keygen_frame, text="Browse...", command=self.browse_output_dir).grid(row=1, column=2, padx=5)
        
        # Key prefix
        ttk.Label(self.keygen_frame, text="Key Filename Prefix:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.key_prefix_var = tk.StringVar(value="rsa_key")
        ttk.Entry(self.keygen_frame, textvariable=self.key_prefix_var, width=50).grid(row=2, column=1, sticky=tk.W+tk.E, padx=5)
        
        # Generate button
        ttk.Button(self.keygen_frame, text="Generate Key Pair", command=self.generate_keys).grid(row=3, column=1, pady=20)
        
        # Progress bar
        self.keygen_progress = ttk.Progressbar(self.keygen_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.keygen_progress.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, pady=10)
        
        # Configure grid
        self.keygen_frame.columnconfigure(1, weight=1)
    
    def setup_encrypt_tab(self):
        # Input file
        ttk.Label(self.encrypt_frame, text="Input File:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.encrypt_input_var = tk.StringVar()
        ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_input_var, width=50).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.encrypt_frame, text="Browse...", command=self.browse_encrypt_input).grid(row=0, column=2, padx=5)
        
        # Public key file
        ttk.Label(self.encrypt_frame, text="Public Key File:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.encrypt_key_var = tk.StringVar()
        ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_key_var, width=50).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.encrypt_frame, text="Browse...", command=self.browse_encrypt_key).grid(row=1, column=2, padx=5)
        
        # Output file
        ttk.Label(self.encrypt_frame, text="Output File:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.encrypt_output_var = tk.StringVar()
        ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_output_var, width=50).grid(row=2, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.encrypt_frame, text="Browse...", command=self.browse_encrypt_output).grid(row=2, column=2, padx=5)
        
        # Encrypt button
        ttk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt).grid(row=3, column=1, pady=20)
        
        # Progress bar
        self.encrypt_progress = ttk.Progressbar(self.encrypt_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.encrypt_progress.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, pady=10)
        
        # Configure grid
        self.encrypt_frame.columnconfigure(1, weight=1)
    
    def setup_decrypt_tab(self):
        # Input file
        ttk.Label(self.decrypt_frame, text="Input File:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.decrypt_input_var = tk.StringVar()
        ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_input_var, width=50).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.decrypt_frame, text="Browse...", command=self.browse_decrypt_input).grid(row=0, column=2, padx=5)
        
        # Private key file
        ttk.Label(self.decrypt_frame, text="Private Key File:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.decrypt_key_var = tk.StringVar()
        ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_key_var, width=50).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.decrypt_frame, text="Browse...", command=self.browse_decrypt_key).grid(row=1, column=2, padx=5)
        
        # Output file
        ttk.Label(self.decrypt_frame, text="Output File:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.decrypt_output_var = tk.StringVar()
        ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_output_var, width=50).grid(row=2, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.decrypt_frame, text="Browse...", command=self.browse_decrypt_output).grid(row=2, column=2, padx=5)
        
        # Decrypt button
        ttk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt).grid(row=3, column=1, pady=20)
        
        # Progress bar
        self.decrypt_progress = ttk.Progressbar(self.decrypt_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.decrypt_progress.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, pady=10)
        
        # Configure grid
        self.decrypt_frame.columnconfigure(1, weight=1)
    
    # File browsing functions
    def browse_output_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir_var.set(directory)
    
    def browse_encrypt_input(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.encrypt_input_var.set(filename)
            # Automatically set output filename
            output_filename = filename + ".enc"
            self.encrypt_output_var.set(output_filename)
    
    def browse_encrypt_key(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.encrypt_key_var.set(filename)
    
    def browse_encrypt_output(self):
        filename = filedialog.asksaveasfilename(defaultextension=".enc")
        if filename:
            self.encrypt_output_var.set(filename)
    
    def browse_decrypt_input(self):
        filename = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if filename:
            self.decrypt_input_var.set(filename)
            # Automatically set output filename (remove .enc if present)
            if filename.endswith(".enc"):
                output_filename = filename[:-4]
            else:
                output_filename = filename + ".dec"
            self.decrypt_output_var.set(output_filename)
    
    def browse_decrypt_key(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.decrypt_key_var.set(filename)
    
    def browse_decrypt_output(self):
        filename = filedialog.asksaveasfilename()
        if filename:
            self.decrypt_output_var.set(filename)
    
    # Core functionality
    def generate_keys(self):
        # Get parameters
        key_size = int(self.key_size_var.get())
        output_dir = self.output_dir_var.get()
        key_prefix = self.key_prefix_var.get()
        
        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory")
            return
        
        # Start progress bar
        self.keygen_progress.start()
        self.status_var.set("Generating keys... This may take a while.")
        self.root.update_idletasks()
        
        # Generate keys in a separate thread to avoid freezing the UI
        self.root.after(100, self.do_generate_keys, key_size, output_dir, key_prefix)
    
    def do_generate_keys(self, key_size, output_dir, key_prefix):
        try:
            # Generate key pair
            public_key, private_key, p, q = generate_keypair(key_size)
            
            # Save keys to files
            public_key_file = os.path.join(output_dir, f"{key_prefix}_public.txt")
            private_key_file = os.path.join(output_dir, f"{key_prefix}_private.txt")
            
            save_key_to_file(public_key, public_key_file)
            save_key_to_file((private_key[0], private_key[1], p, q), private_key_file)
            
            # Stop progress bar
            self.keygen_progress.stop()
            self.status_var.set("Keys generated successfully")
            
            messagebox.showinfo("Success", f"Keys generated and saved to:\n{public_key_file}\n{private_key_file}")
        
        except Exception as e:
            # Stop progress bar
            self.keygen_progress.stop()
            self.status_var.set("Error generating keys")
            
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
    
    def encrypt(self):
        # Get parameters
        input_file = self.encrypt_input_var.get()
        key_file = self.encrypt_key_var.get()
        output_file = self.encrypt_output_var.get()
        
        if not input_file or not key_file or not output_file:
            messagebox.showerror("Error", "Please select all required files")
            return
        
        # Start progress bar
        self.encrypt_progress.start()
        self.status_var.set("Encrypting... This may take a while.")
        self.root.update_idletasks()
        
        # Encrypt in a separate thread
        self.root.after(100, self.do_encrypt, input_file, key_file, output_file)
    
    def do_encrypt(self, input_file, key_file, output_file):
        try:
            # Encrypt file
            encrypt_file(input_file, output_file, key_file)
            
            # Stop progress bar
            self.encrypt_progress.stop()
            self.status_var.set("File encrypted successfully")
            
            messagebox.showinfo("Success", f"File encrypted and saved to:\n{output_file}")
        
        except Exception as e:
            # Stop progress bar
            self.encrypt_progress.stop()
            self.status_var.set("Error encrypting file")
            
            messagebox.showerror("Error", f"Failed to encrypt file: {str(e)}")
    
    def decrypt(self):
        # Get parameters
        input_file = self.decrypt_input_var.get()
        key_file = self.decrypt_key_var.get()
        output_file = self.decrypt_output_var.get()
        
        if not input_file or not key_file or not output_file:
            messagebox.showerror("Error", "Please select all required files")
            return
        
        # Start progress bar
        self.decrypt_progress.start()
        self.status_var.set("Decrypting... This may take a while.")
        self.root.update_idletasks()
        
        # Decrypt in a separate thread
        self.root.after(100, self.do_decrypt, input_file, key_file, output_file)
    
    def do_decrypt(self, input_file, key_file, output_file):
        try:
            # Decrypt file (may return a modified output filename)
            actual_output_file = decrypt_file(input_file, output_file, key_file)
            
            # Update the output filename in the GUI if it was changed
            if actual_output_file != output_file:
                self.decrypt_output_var.set(actual_output_file)
                output_file = actual_output_file
            
            # Stop progress bar
            self.decrypt_progress.stop()
            self.status_var.set("File decrypted successfully")
            
            messagebox.showinfo("Success", f"File decrypted and saved to:\n{output_file}")
        
        except Exception as e:
            # Stop progress bar
            self.decrypt_progress.stop()
            self.status_var.set(f"Error decrypting file: {str(e)}")
            
            # Show detailed error message
            error_details = traceback.format_exc()
            
            messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}\n\nDetails: {error_details}")
            
            # Log error to console
            print("Decryption error details:")
            print(error_details)