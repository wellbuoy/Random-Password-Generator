# Import necessary modules
import tkinter as tk
from tkinter import ttk
import random
import string
from tkinter import messagebox
import pyperclip

# define the PasswordGeneratorApp class
class PasswordGeneratorApp:
    def __init__(self, master):
        
        # initialize the application
        self.master = master
        self.master.title("Password Generator")  # Set window title
        
        # initialize variables to store user options and generated password
        self.length_var = tk.IntVar()
        self.length_var.set(15)  # Default length
        self.include_upper_var = tk.BooleanVar()
        self.include_lower_var = tk.BooleanVar()
        self.include_digits_var = tk.BooleanVar()
        self.include_symbols_var = tk.BooleanVar()
        self.password_var = tk.StringVar()
        
        # create GUI elements
        self.create_widgets()
        
    def create_widgets(self):

        # password length label and entry
        length_label = ttk.Label(self.master, text="Length:")
        length_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        length_entry = ttk.Entry(self.master, textvariable=self.length_var)
        length_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        # character options checkboxes
        include_upper_check = ttk.Checkbutton(self.master, text="Include Uppercase", variable=self.include_upper_var)
        include_upper_check.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        
        include_lower_check = ttk.Checkbutton(self.master, text="Include Lowercase", variable=self.include_lower_var)
        include_lower_check.grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        
        include_digits_check = ttk.Checkbutton(self.master, text="Include Digits", variable=self.include_digits_var)
        include_digits_check.grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        
        include_symbols_check = ttk.Checkbutton(self.master, text="Include Symbols", variable=self.include_symbols_var)
        include_symbols_check.grid(row=4, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        
        # generate password button
        generate_button = ttk.Button(self.master, text="Generate Password", command=self.generate_password)
        generate_button.grid(row=5, column=0, columnspan=2, pady=10)
        
        # display generated password
        password_label = ttk.Label(self.master, text="Generated Password:")
        password_label.grid(row=6, column=0, sticky="w", padx=5, pady=5)
        password_entry = ttk.Entry(self.master, textvariable=self.password_var, state="readonly")
        password_entry.grid(row=6, column=1, sticky="w", padx=5, pady=5)
        
        # copy to clipboard button
        copy_button = ttk.Button(self.master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        copy_button.grid(row=7, column=0, columnspan=2, pady=10)
        
    def generate_password(self):

        # generate a password based on user options
        length = self.length_var.get()
        include_upper = self.include_upper_var.get()
        include_lower = self.include_lower_var.get()
        include_digits = self.include_digits_var.get()
        include_symbols = self.include_symbols_var.get()
        
        characters = ''
        if include_upper:
            characters += string.ascii_uppercase
        if include_lower:
            characters += string.ascii_lowercase
        if include_digits:
            characters += string.digits
        if include_symbols:
            characters += string.punctuation
        
        if not characters:
            tk.messagebox.showwarning("Warning", "Please tick at least one box or more.")
            return
        
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)
        
    def copy_to_clipboard(self):

        # copy the generated password to clipboard
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            tk.messagebox.showinfo("Success", "Password copied to clipboard.")
        else:
            tk.messagebox.showwarning("Warning", "No password generated.")

# main function to run the application
def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

# run the main function if this script is executed
if __name__ == "__main__":
    main()
