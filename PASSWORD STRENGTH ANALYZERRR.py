import tkinter as tk
from tkinter import messagebox
import re
import hashlib
import sqlite3
import secrets
import string


# =========================================================
# DATABASE
# =========================================================

def create_database():
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT UNIQUE
        )
    """)

    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def password_was_used(password):
    password_hash = hash_password(password)

    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash FROM password_history WHERE password_hash = ?",
        (password_hash,)
    )

    result = cursor.fetchone()

    conn.close()

    return result is not None


def save_password(password):
    password_hash = hash_password(password)

    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO password_history (password_hash) VALUES (?)",
            (password_hash,)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass

    conn.close()


# =========================================================
# PASSWORD GENERATOR
# =========================================================

def generate_password():
    characters = (
        string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        "!@#$%^&*"
    )

    password = (
        secrets.choice(string.ascii_uppercase) +
        secrets.choice(string.ascii_lowercase) +
        secrets.choice(string.digits) +
        secrets.choice("!@#$%^&*")
    )

    password += "".join(
        secrets.choice(characters)
        for _ in range(12)
    )

    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)

    generated = "".join(password_list)

    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated)

    analyze_password()


# =========================================================
# PASSWORD ANALYSIS
# =========================================================

def analyze_password():

    password = password_entry.get()

    if not password:
        reset_result()
        return

    score = 0
    suggestions = []

    # -----------------------------------------------------
    # LENGTH
    # -----------------------------------------------------

    if len(password) >= 12:
        score += 30
        length_status = True

    elif len(password) >= 8:
        score += 20
        length_status = True
        suggestions.append(
            "Use 12 or more characters for better security."
        )

    else:
        length_status = False
        suggestions.append(
            "Use at least 8 characters."
        )

    # -----------------------------------------------------
    # LOWERCASE
    # -----------------------------------------------------

    lowercase = bool(re.search(r"[a-z]", password))

    if lowercase:
        score += 10
    else:
        suggestions.append(
            "Add lowercase letters."
        )

    # -----------------------------------------------------
    # UPPERCASE
    # -----------------------------------------------------

    uppercase = bool(re.search(r"[A-Z]", password))

    if uppercase:
        score += 10
    else:
        suggestions.append(
            "Add uppercase letters."
        )

    # -----------------------------------------------------
    # NUMBERS
    # -----------------------------------------------------

    numbers = bool(re.search(r"[0-9]", password))

    if numbers:
        score += 15
    else:
        suggestions.append(
            "Add numbers."
        )

    # -----------------------------------------------------
    # SPECIAL CHARACTERS
    # -----------------------------------------------------

    special = bool(
        re.search(r"[^A-Za-z0-9]", password)
    )

    if special:
        score += 15
    else:
        suggestions.append(
            "Add special characters such as @, #, $, !."
        )

    # -----------------------------------------------------
    # REPEATED CHARACTERS
    # -----------------------------------------------------

    repeated = bool(
        re.search(r"(.)\1\1", password)
    )

    if repeated:
        score -= 10
        suggestions.append(
            "Avoid repeating the same character multiple times."
        )

    # -----------------------------------------------------
    # COMMON PASSWORDS
    # -----------------------------------------------------

    common_passwords = [
        "password",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "admin",
        "password123",
        "admin123",
        "letmein",
        "welcome"
    ]

    if password.lower() in common_passwords:

        score = 5

        suggestions.insert(
            0,
            "This is a commonly used password. Choose a unique one."
        )

    # -----------------------------------------------------
    # UNIQUENESS / PASSWORD HISTORY
    # -----------------------------------------------------

    already_used = password_was_used(password)

    if already_used:

        uniqueness_status = False

        suggestions.insert(
            0,
            "This password has already been used. Choose a new one."
        )

        score = min(score, 40)

    else:
        uniqueness_status = True

    # Keep score between 0 and 100
    score = max(0, min(score, 100))

    # -----------------------------------------------------
    # STRENGTH LEVEL
    # -----------------------------------------------------

    if score < 30:
        strength = "VERY WEAK"
        status_color = "#dc3545"

    elif score < 50:
        strength = "WEAK"
        status_color = "#fd7e14"

    elif score < 75:
        strength = "MEDIUM"
        status_color = "#ffc107"

    elif score < 90:
        strength = "STRONG"
        status_color = "#20c997"

    else:
        strength = "VERY STRONG"
        status_color = "#198754"

    # -----------------------------------------------------
    # UPDATE GUI
    # -----------------------------------------------------

    score_label.config(
        text=f"{score}/100",
        fg=status_color
    )

    strength_label.config(
        text=strength,
        fg=status_color
    )

    progress_canvas.delete("all")

    progress_canvas.create_rectangle(
        0,
        0,
        score * 4.8,
        18,
        fill=status_color,
        outline=""
    )

    # Requirements

    update_check(
        length_label,
        length_status,
        "At least 8 characters"
    )

    update_check(
        lowercase_label,
        lowercase,
        "Lowercase letter"
    )

    update_check(
        uppercase_label,
        uppercase,
        "Uppercase letter"
    )

    update_check(
        number_label,
        numbers,
        "Number"
    )

    update_check(
        special_label,
        special,
        "Special character"
    )

    update_check(
        unique_label,
        uniqueness_status,
        "Unique / not previously used"
    )

    # Suggestions

    suggestion_box.config(state="normal")
    suggestion_box.delete("1.0", tk.END)

    if not suggestions:

        suggestion_box.insert(
            tk.END,
            "✓ Excellent password!\n\n"
            "Your password satisfies all the basic "
            "security requirements."
        )

    else:

        for suggestion in suggestions:
            suggestion_box.insert(
                tk.END,
                "• " + suggestion + "\n"
            )

    suggestion_box.config(state="disabled")


# =========================================================
# GUI HELPERS
# =========================================================

def update_check(label, condition, text):

    if condition:

        label.config(
            text="✓ " + text,
            fg="#198754"
        )

    else:

        label.config(
            text="○ " + text,
            fg="#777777"
        )


def toggle_password():

    if password_entry.cget("show") == "*":

        password_entry.config(show="")
        show_button.config(text="Hide")

    else:

        password_entry.config(show="*")
        show_button.config(text="Show")


def use_password():

    password = password_entry.get()

    if not password:
        messagebox.showwarning(
            "No Password",
            "Please enter a password first."
        )
        return

    if password_was_used(password):

        messagebox.showwarning(
            "Password Reused",
            "This password has already been used.\n\n"
            "Please choose a new password."
        )

        return

    save_password(password)

    messagebox.showinfo(
        "Password Saved",
        "Password accepted.\n\n"
        "Only its SHA-256 hash has been stored."
    )

    analyze_password()


def clear_password():

    password_entry.delete(0, tk.END)

    score_label.config(
        text="0/100",
        fg="#333333"
    )

    strength_label.config(
        text="Enter a password",
        fg="#777777"
    )

    progress_canvas.delete("all")

    for label in [
        length_label,
        lowercase_label,
        uppercase_label,
        number_label,
        special_label,
        unique_label
    ]:

        label.config(
            fg="#777777"
        )

    suggestion_box.config(state="normal")

    suggestion_box.delete(
        "1.0",
        tk.END
    )

    suggestion_box.insert(
        tk.END,
        "Enter a password to get security recommendations."
    )

    suggestion_box.config(state="disabled")


def reset_result():
    clear_password()


# =========================================================
# MAIN WINDOW
# =========================================================

create_database()

root = tk.Tk()

root.title(
    "Password Strength Analyzer"
)

root.geometry(
    "700x780"
)

root.resizable(
    False,
    False
)

root.configure(
    bg="#f4f6f8"
)


# =========================================================
# HEADER
# =========================================================

header = tk.Frame(
    root,
    bg="#172033",
    height=110
)

header.pack(
    fill="x"
)

tk.Label(
    header,
    text="🔐 Password Strength Analyzer",
    font=("Segoe UI", 24, "bold"),
    fg="white",
    bg="#172033"
).pack(pady=(22, 3))

tk.Label(
    header,
    text="Evaluate password security and prevent password reuse",
    font=("Segoe UI", 10),
    fg="#cbd5e1",
    bg="#172033"
).pack()


# =========================================================
# MAIN CARD
# =========================================================

card = tk.Frame(
    root,
    bg="white",
    padx=35,
    pady=25
)

card.pack(
    padx=40,
    pady=25,
    fill="both"
)


# =========================================================
# PASSWORD INPUT
# =========================================================

tk.Label(
    card,
    text="Enter Password",
    font=("Segoe UI", 12, "bold"),
    bg="white",
    fg="#172033"
).pack(anchor="w")


input_frame = tk.Frame(
    card,
    bg="white"
)

input_frame.pack(
    fill="x",
    pady=8
)


password_entry = tk.Entry(
    input_frame,
    font=("Segoe UI", 14),
    show="*",
    relief="solid",
    bd=1
)

password_entry.pack(
    side="left",
    fill="x",
    expand=True,
    ipady=8
)

password_entry.bind(
    "<KeyRelease>",
    lambda event: analyze_password()
)


show_button = tk.Button(
    input_frame,
    text="Show",
    command=toggle_password,
    relief="flat",
    bg="#e9ecef",
    padx=15
)

show_button.pack(
    side="right",
    padx=(8, 0),
    ipady=7
)


# =========================================================
# SCORE
# =========================================================

result_frame = tk.Frame(
    card,
    bg="white"
)

result_frame.pack(
    fill="x",
    pady=(15, 5)
)


score_label = tk.Label(
    result_frame,
    text="0/100",
    font=("Segoe UI", 28, "bold"),
    bg="white"
)

score_label.pack(
    side="left"
)


strength_label = tk.Label(
    result_frame,
    text="Enter a password",
    font=("Segoe UI", 14, "bold"),
    bg="white",
    fg="#777777"
)

strength_label.pack(
    side="right"
)


# =========================================================
# PROGRESS BAR
# =========================================================

progress_canvas = tk.Canvas(
    card,
    width=480,
    height=18,
    bg="#e9ecef",
    highlightthickness=0
)

progress_canvas.pack(
    fill="x",
    pady=(5, 20)
)


# =========================================================
# REQUIREMENTS
# =========================================================

tk.Label(
    card,
    text="Security Requirements",
    font=("Segoe UI", 13, "bold"),
    bg="white"
).pack(
    anchor="w",
    pady=(5, 8)
)


length_label = tk.Label(
    card,
    text="○ At least 8 characters",
    font=("Segoe UI", 10),
    bg="white",
    fg="#777777"
)

length_label.pack(anchor="w")


lowercase_label = tk.Label(
    card,
    text="○ Lowercase letter",
    font=("Segoe UI", 10),
    bg="white",
    fg="#777777"
)

lowercase_label.pack(anchor="w")


uppercase_label = tk.Label(
    card,
    text="○ Uppercase letter",
    font=("Segoe UI", 10),
    bg="white",
    fg="#777777"
)

uppercase_label.pack(anchor="w")


number_label = tk.Label(
    card,
    text="○ Number",
    font=("Segoe UI", 10),
    bg="white",
    fg="#777777"
)

number_label.pack(anchor="w")


special_label = tk.Label(
    card,
    text="○ Special character",
    font=("Segoe UI", 10),
    bg="white",
    fg="#777777"
)

special_label.pack(anchor="w")


unique_label = tk.Label(
    card,
    text="○ Unique / not previously used",
    font=("Segoe UI", 10),
    bg="white",
    fg="#777777"
)

unique_label.pack(anchor="w")


# =========================================================
# SUGGESTIONS
# =========================================================

tk.Label(
    card,
    text="Suggestions",
    font=("Segoe UI", 13, "bold"),
    bg="white"
).pack(
    anchor="w",
    pady=(18, 5)
)


suggestion_box = tk.Text(
    card,
    height=4,
    font=("Segoe UI", 10),
    bg="#f8f9fa",
    fg="#555555",
    relief="solid",
    bd=1,
    wrap="word"
)

suggestion_box.pack(
    fill="x"
)

suggestion_box.insert(
    tk.END,
    "Enter a password to get security recommendations."
)

suggestion_box.config(
    state="disabled"
)


# =========================================================
# BUTTONS
# =========================================================

button_frame = tk.Frame(
    card,
    bg="white"
)

button_frame.pack(
    pady=18
)


tk.Button(
    button_frame,
    text="⚡ Generate Strong Password",
    command=generate_password,
    font=("Segoe UI", 10, "bold"),
    bg="#0d6efd",
    fg="white",
    relief="flat",
    padx=15,
    pady=8
).pack(
    side="left",
    padx=5
)


tk.Button(
    button_frame,
    text="Use Password",
    command=use_password,
    font=("Segoe UI", 10, "bold"),
    bg="#198754",
    fg="white",
    relief="flat",
    padx=20,
    pady=8
).pack(
    side="left",
    padx=5
)


tk.Button(
    button_frame,
    text="Clear",
    command=clear_password,
    font=("Segoe UI", 10),
    bg="#e9ecef",
    relief="flat",
    padx=20,
    pady=8
).pack(
    side="left",
    padx=5
)


# =========================================================
# FOOTER
# =========================================================

tk.Label(
    root,
    text="🔒 Passwords are never stored in plain text.",
    font=("Segoe UI", 9),
    bg="#f4f6f8",
    fg="#666666"
).pack(
    pady=(0, 10)
)


root.mainloop()