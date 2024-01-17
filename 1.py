import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string


def generate_password(length=12, use_uppercase=True, use_digits=True, use_special_chars=True):
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    return password


def generate_password_button_clicked():
    length = int(length_var.get())
    use_uppercase = uppercase_var.get()
    use_digits = digits_var.get()
    use_special_chars = special_chars_var.get()

    password = generate_password(length, use_uppercase, use_digits, use_special_chars)
    result_var.set(password)


def copy_to_clipboard():
    password = result_var.get()

    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()
    messagebox.showinfo("Копирование", "Пароль скопирован в буфер обмена")


root = tk.Tk()
root.title("Генератор паролей")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(frame, text="Длина пароля:").grid(row=0, column=0, sticky=tk.W)
length_var = tk.StringVar()
length_entry = ttk.Entry(frame, textvariable=length_var)
length_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

uppercase_var = tk.BooleanVar()
uppercase_checkbutton = ttk.Checkbutton(frame, text="Заглавные буквы", variable=uppercase_var)
uppercase_checkbutton.grid(row=1, column=0, sticky=tk.W)

digits_var = tk.BooleanVar()
digits_checkbutton = ttk.Checkbutton(frame, text="Цифры", variable=digits_var)
digits_checkbutton.grid(row=2, column=0, sticky=tk.W)

special_chars_var = tk.BooleanVar()
special_chars_checkbutton = ttk.Checkbutton(frame, text="Специальные символы", variable=special_chars_var)
special_chars_checkbutton.grid(row=3, column=0, sticky=tk.W)

generate_button = ttk.Button(frame, text="Сгенерировать пароль", command=generate_password_button_clicked)
generate_button.grid(row=4, column=0, columnspan=2, pady=(10, 0))

result_var = tk.StringVar()
result_entry = ttk.Entry(frame, textvariable=result_var, state="readonly", width=30)
result_entry.grid(row=5, column=0, columnspan=2, pady=(10, 0))

copy_button = ttk.Button(frame, text="Копировать в буфер", command=copy_to_clipboard)
copy_button.grid(row=6, column=0, columnspan=2, pady=(10, 0))


root.mainloop()
