import atexit
import tkinter.simpledialog
import tkinter as tk
from datetime import datetime
from tkinter import ttk
from tkinter import messagebox
from kljucevi import *
from public_key_ring import PublicKeyRing
from private_key_ring import PrivateKeyRing
from pgp_funkcionalnosti import *
from message import Message
import os
import pgp_funkcionalnosti

public_key_ring = PublicKeyRing()
private_key_ring = PrivateKeyRing()
username = ""


def save_key_rings():
    public_key_ring.save_to_file(username)
    private_key_ring.save_to_file(username)


atexit.register(save_key_rings)


def generate_keys_wrapper():
    def generate():
        name = name_entry.get()
        email = email_entry.get()
        password = password_entry.get()

        if not name or not email or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        key_size = key_size_var.get()
        if not key_size:
            messagebox.showerror("Error", "Please select a key size.")
            return

        key_id, public_key, private_key = generate_keys(password, key_size)
        public_key_ring.add_key(key_id, public_key, name, email)
        private_key_ring.add_key(key_id, public_key, private_key, name, email)

        # messagebox.showinfo("Success", f"Keys generated successfully. Key ID: {key_id}")
        window.destroy()

    window = tk.Toplevel()
    window.title("Generate Keys")

    name_label = ttk.Label(window, text="Name:")
    name_label.grid(row=0, column=0, padx=5, pady=5)
    name_entry = ttk.Entry(window)
    name_entry.grid(row=0, column=1, padx=5, pady=5)

    email_label = ttk.Label(window, text="Email:")
    email_label.grid(row=1, column=0, padx=5, pady=5)
    email_entry = ttk.Entry(window)
    email_entry.grid(row=1, column=1, padx=5, pady=5)

    key_size_label = ttk.Label(window, text="Key Size:")
    key_size_label.grid(row=2, column=0, padx=5, pady=5)

    key_size_var = tk.IntVar()
    key_size_var.set(1024)
    key_size_1024 = ttk.Radiobutton(window, text="1024 bits", variable=key_size_var, value=1024)
    key_size_1024.grid(row=2, column=1, padx=5, pady=5, sticky="w")
    key_size_2048 = ttk.Radiobutton(window, text="2048 bits", variable=key_size_var, value=2048)
    key_size_2048.grid(row=3, column=1, padx=5, pady=5, sticky="w")

    password_label = ttk.Label(window, text="Password:")
    password_label.grid(row=4, column=0, padx=5, pady=5)
    password_entry = ttk.Entry(window, show="*")
    password_entry.grid(row=4, column=1, padx=5, pady=5)

    generate_button = ttk.Button(window, text="Generate", command=generate)
    generate_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="ew")


def view_public_key_ring():
    window = tk.Toplevel()
    window.title("Public Key Ring")

    tree = ttk.Treeview(window)
    tree["columns"] = ("Timestamp", "Key ID", "Public key", "Name", "Email")
    # tree.heading("#0", text="Index")
    tree.heading("Timestamp", text="Timestamp")
    tree.heading("Key ID", text="Key ID")
    tree.heading("Public key", text="Public key")
    tree.heading("Name", text="Name")
    tree.heading("Email", text="Email")

    key_values = public_key_ring.get_key_values()
    for i, values in enumerate(key_values, start=1):
        tree.insert("", "end", text=str(i), values=values)

    tree.pack(expand=True, fill="both")


def view_private_key_ring():
    def view_encrypted_password():
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a row.")
            return
        item = tree.item(selected_item)
        key_id = item['values'][1]  # Key ID

        password = tkinter.simpledialog.askstring("Password", "Enter your password:", show="*")
        if password is None:
            return

        encrypted_private_key = private_key_ring.find_key_keyid(key_id)["Encrypted private key"]
        decrypted_private_key = decrypt_private_key(encrypted_private_key, password)
        if decrypted_private_key:
            messagebox.showinfo("Decrypted private key", "Decrypted private key:\n" + decrypted_private_key.hex())
        else:
            messagebox.showerror("Failure", f"Incorrect password!")

    window = tk.Toplevel()
    window.title("Private Key Ring")

    tree = ttk.Treeview(window)
    tree["columns"] = ("Timestamp", "Key ID", "Public key", "Encrypted private key", "Name", "Email")
    # tree.heading("#0", text="Index")
    tree.heading("Timestamp", text="Timestamp")
    tree.heading("Key ID", text="Key ID")
    tree.heading("Public key", text="Public key")
    tree.heading("Encrypted private key", text="Encrypted private key")
    tree.heading("Name", text="Name")
    tree.heading("Email", text="Email")

    key_values = private_key_ring.get_key_values()
    for i, values in enumerate(key_values, start=1):
        tree.insert("", "end", text=str(i), values=values)

    tree.pack(expand=True, fill="both")

    view_password_button = ttk.Button(window, text="View Encrypted Password", command=view_encrypted_password)
    view_password_button.pack(pady=5)


def load_keys():
    def load():
        file = filename_entry.get()
        name = name_entry.get()
        email = email_entry.get()

        if not file or not name or not email:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        key_id = file.split("_")[0]
        new_public_key = load_public_key(key_id)
        public_key_ring.add_key(key_id, new_public_key, name, email)

        window.destroy()

    window = tk.Toplevel()
    window.title("Load Users Public Key")

    filename_label = ttk.Label(window, text="File name:")
    filename_label.grid(row=0, column=0, padx=5, pady=5)
    filename_entry = ttk.Entry(window)
    filename_entry.grid(row=0, column=1, padx=5, pady=5)

    name_label = ttk.Label(window, text="Name:")
    name_label.grid(row=1, column=0, padx=5, pady=5)
    name_entry = ttk.Entry(window)
    name_entry.grid(row=1, column=1, padx=5, pady=5)

    email_label = ttk.Label(window, text="Email:")
    email_label.grid(row=2, column=0, padx=5, pady=5)
    email_entry = ttk.Entry(window)
    email_entry.grid(row=2, column=1, padx=5, pady=5)

    generate_button = ttk.Button(window, text="Load", command=load)
    generate_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="ew")


def load_key_pairs():
    def load():
        file = filename_entry.get()
        name = name_entry.get()
        email = email_entry.get()
        password_private_key = password_entry.get()

        if not file or not name or not email:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        key_id = file.split("_")[0]
        print(key_id)

        new_public_key, new_private_key = load_keys_from_file(key_id, password_private_key)
        public_key_ring.add_key(key_id, new_public_key, name, email)
        private_key_ring.add_key(key_id, new_public_key, new_private_key, name, email)

        window.destroy()

    window = tk.Toplevel()
    window.title("Load Keys From File")

    filename_label = ttk.Label(window, text="File name:")
    filename_label.grid(row=0, column=0, padx=5, pady=5)
    filename_entry = ttk.Entry(window)
    filename_entry.grid(row=0, column=1, padx=5, pady=5)

    name_label = ttk.Label(window, text="Name:")
    name_label.grid(row=1, column=0, padx=5, pady=5)
    name_entry = ttk.Entry(window)
    name_entry.grid(row=1, column=1, padx=5, pady=5)

    email_label = ttk.Label(window, text="Email:")
    email_label.grid(row=2, column=0, padx=5, pady=5)
    email_entry = ttk.Entry(window)
    email_entry.grid(row=2, column=1, padx=5, pady=5)

    password_label = ttk.Label(window, text="Password used for private key:")
    password_label.grid(row=3, column=0, padx=5, pady=5)
    password_entry = ttk.Entry(window, show="*")
    password_entry.grid(row=3, column=1, padx=5, pady=5, )

    generate_button = ttk.Button(window, text="Load", command=load)
    generate_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="ew")


def send_message():
    message_final = Message()

    def sign_wrapper(message):

        result = [message]

        # treba da se doda da returnuje password koji je dekriptovan
        def view_encrypted_password():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showinfo("Info", "Please select a row.")
                return
            item = tree.item(selected_item)
            key_id = item['values'][1]

            password = tkinter.simpledialog.askstring("Password", "Enter your password:", show="*")
            if password is None:
                return

            encrypted_private_key = private_key_ring.find_key_keyid(key_id)["Encrypted private key"]
            decrypted_private_key = decrypt_private_key(encrypted_private_key, password)
            if decrypted_private_key:
                # message_final.set_sender_key_id(key_id)
                potpis = sign_message(result[0], decrypted_private_key)
                result[0] = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + str(key_id) + str(potpis) + result[0]
                print("---------------------")
                print(potpis)
                print(len(str(potpis)))
                window.destroy()
                # message_final.set_message_digest(sign_message(message_text.get("1.0", "end-1c"), decrypted_private_key))
            else:
                messagebox.showerror("Failure", f"Incorrect password!")

        window = tk.Toplevel()
        window.title("Sign Message")

        tree = ttk.Treeview(window)
        tree["columns"] = ("Timestamp", "Key ID", "Public key", "Encrypted private key", "Name", "Email")
        tree.heading("Timestamp", text="Timestamp")
        tree.heading("Key ID", text="Key ID")
        tree.heading("Public key", text="Public key")
        tree.heading("Encrypted private key", text="Encrypted private key")
        tree.heading("Name", text="Name")
        tree.heading("Email", text="Email")

        key_values = private_key_ring.get_key_values()
        for i, values in enumerate(key_values, start=1):
            tree.insert("", "end", text=str(i), values=values)

        tree.pack(expand=True, fill="both")

        view_password_button = ttk.Button(window, text="Pick the key", command=view_encrypted_password)
        view_password_button.pack(pady=5)
        window.wait_window()
        print(type(result[0]))
        return result[0]

    def encrypt_message_wrapper(message):
        result = [message]

        def encrypt():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showinfo("Info", "Please select a public key for encryption.")
                return
            item = tree.item(selected_item)
            key_id = item['values'][1]
            public_key = public_key_ring.find_key_keyid(key_id)["Public key"]
            # message_final.set_receiver_key_id(key_id)

            encrypted_key, encrypted_message = encrypt_message(  # encrypted key = session key
                result[0],
                public_key,
                algorithm_var.get()
            )

            # message_final.set_session_key(encrypted_key)
            print(result[0])
            result[0] = encrypted_key + encrypted_message
            print(len(encrypted_key))
            print(encrypted_key)
            result[0] = int(key_id[-16:], 16).to_bytes(8, byteorder='big') + result[0]
            if algorithm_var.get() == 'AES':
                result[0] = b'\x00' + result[0]
            else:
                result[0] = b'\x01' + result[0]

            window.destroy()

        window = tk.Toplevel()
        window.title("Encrypt Message")

        tree = ttk.Treeview(window)
        tree["columns"] = ("Timestamp", "Key ID", "Public key", "Name", "Email")
        tree.heading("Timestamp", text="Timestamp")
        tree.heading("Key ID", text="Key ID")
        tree.heading("Public key", text="Public key")
        tree.heading("Name", text="Name")
        tree.heading("Email", text="Email")

        key_values = public_key_ring.get_key_values()
        for i, values in enumerate(key_values, start=1):
            tree.insert("", "end", text=str(i), values=values)

        tree.pack(expand=True, fill="both")

        algorithm_var = tk.StringVar()
        algorithm_var.set("AES")

        algorithm_label = ttk.Label(window, text="Encryption Algorithm:")
        algorithm_label.pack(pady=5)

        aes_radio = ttk.Radiobutton(window, text="AES", variable=algorithm_var, value="AES")
        aes_radio.pack(pady=2)
        cast_radio = ttk.Radiobutton(window, text="CAST", variable=algorithm_var, value="CAST")
        cast_radio.pack(pady=2)

        encrypt_button = ttk.Button(window, text="Encrypt", command=encrypt)
        encrypt_button.pack(pady=5)

        window.wait_window()
        return result[0]

    def compress_message_wrapper(message):
        compressed_message = compress_message(message)
        print(type(compressed_message))
        return compressed_message

    def convert_to_radix64_wrapper(message):
        radix64_data = convert_to_radix64(message)
        return radix64_data

    def on_send():
        message = message_text.get("1.0", "end-1c")
        filename = filename_entry.get()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        destination = destination_entry.get()

        full_message = str(timestamp) + str(filename) + '#' + str(message)

        message_final.set_data(message)
        message_final.set_filename(filename)

        if sign_var.get():
            full_message = sign_wrapper(full_message)

        full_message = compress_message_wrapper(full_message)

        if encrypt_var.get():
            full_message = encrypt_message_wrapper(full_message)

        full_message = convert_to_radix64_wrapper(full_message)

        save_message(destination + "/" + filename, full_message)

        window.destroy()

    window = tk.Toplevel()
    window.title("Send Message")

    filename_label = ttk.Label(window, text="Filename:")
    filename_label.pack(pady=5)
    filename_entry = ttk.Entry(window)
    filename_entry.pack(pady=5)

    message_label = ttk.Label(window, text="Message:")
    message_label.pack(pady=5)
    message_text = tk.Text(window, height=10, width=50)
    message_text.pack(pady=5)

    message_final.set_data(message_text.get("1.0", "end-1c"))
    message_final.set_filename(filename_entry.get())

    sign_var = tk.BooleanVar()
    encrypt_var = tk.BooleanVar()
    compress_var = tk.BooleanVar()
    radix64_var = tk.BooleanVar()

    sign_checkbox = ttk.Checkbutton(window, text="Sign Message", variable=sign_var)
    sign_checkbox.pack(pady=5)

    encryption_checkbox = ttk.Checkbutton(window, text="Encrypt Message", variable=encrypt_var)
    encryption_checkbox.pack(pady=5)

    # compression_checkbox = ttk.Checkbutton(window, text="Compress Message", variable=compress_var)
    # compression_checkbox.pack(pady=5)
    #
    # radix64_checkbox = ttk.Checkbutton(window, text="Convert to Radix-64", variable=radix64_var)
    # radix64_checkbox.pack(pady=5)

    destination_label = ttk.Label(window, text="Destination:")
    destination_label.pack(pady=5)
    destination_entry = ttk.Entry(window)
    destination_entry.pack(pady=5)

    send_button = ttk.Button(window, text="Send", command=on_send)
    send_button.pack(pady=5)


def receive_message():
    user_directory = os.path.join(username)
    if not os.path.exists(user_directory):
        messagebox.showerror("Error", f"No directory found for user {username}")
        return

    def select_message_to_decrypt():
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a message file.")
            return
        item = tree.item(selected_item)
        filename = item['values'][0]
        filepath = os.path.join(user_directory, filename)
        window.destroy()
        decrypt_message(filepath)

    def decrypt_message(filepath):
        with open(filepath, "rb") as file:
            message = file.read()

        def convert_from_radix64_wrapper(message):
            return convert_from_radix64(message)

        def decompress_message_wrapper(message):
            return decompress_message(message)

        def decrypt(message):
            password = tkinter.simpledialog.askstring("Password", "Enter your password:", show="*")
            if password is None:
                return
            algoritam = int.from_bytes(message[0:1], byteorder='big')
            if algoritam == 0:
                a = 'AES'
            else:
                a = 'CAST'

            key_id = message[1:9].hex()

            encrypted_session_key = message[9:128 + 9]
            encrypted_message = message[128 + 9:]
            encrypted_private_key = private_key_ring.find_key_keyid(key_id)["Encrypted private key"]
            decrypted_private_key = decrypt_private_key(encrypted_private_key, password)
            print(decrypted_private_key.hex())
            decrypted_message = pgp_funkcionalnosti.decrypt_message(encrypted_session_key, encrypted_message,
                                                                    decrypted_private_key, a)
            print(decrypted_message)
            return decrypted_message

        def check_signature(message):
            timestamp = message[:19]
            print(timestamp)
            key_id = message[19:19 + 16]
            print(key_id)
            potpis = message[19 + 16:19 + 16 + 308]
            data = message[19 + 16 + 308:]
            public_key = public_key_ring.find_key_keyid(key_id)["Public key"]
            print(type(public_key))
            if verify_signature(data, int(potpis), public_key):
                return data
            else:
                return

        def on_read(message):

            message = convert_from_radix64_wrapper(message)

            if encrypt_var.get():
                message = decrypt(message)

            message = decompress_message_wrapper(message)

            if sign_var.get():
                message = check_signature(message)
            time = message[:19]
            parts = message[19:].split('#')
            file_name = parts[0]
            poruka = parts[1]

            window = tk.Toplevel()
            window.title("Message Details")

            tk.Label(window, text=f"Time: {time}").pack(pady=10)
            tk.Label(window, text=f"File Name: {file_name}").pack(pady=10)
            tk.Label(window, text=f"Message: {poruka}").pack(pady=10)

            tk.Button(window, text="Close", command=window.destroy).pack(pady=20)
            delete_message(username + "/" + file_name)
            window.mainloop()

        window = tk.Toplevel()
        window.title("Read Message")

        sign_var = tk.BooleanVar()
        encrypt_var = tk.BooleanVar()
        compress_var = tk.BooleanVar()
        radix64_var = tk.BooleanVar()

        sign_checkbox = ttk.Checkbutton(window, text="Sign Message", variable=sign_var)
        sign_checkbox.pack(pady=5)

        encryption_checkbox = ttk.Checkbutton(window, text="Encrypt Message", variable=encrypt_var)
        encryption_checkbox.pack(pady=5)

        # compression_checkbox = ttk.Checkbutton(window, text="Compress Message", variable=compress_var)
        # compression_checkbox.pack(pady=5)
        #
        # radix64_checkbox = ttk.Checkbutton(window, text="Convert to Radix-64", variable=radix64_var)
        # radix64_checkbox.pack(pady=5)

        send_button = ttk.Button(window, text="Read", command=lambda: on_read(message))

        send_button.pack(pady=5)

        window.wait_window()

    window = tk.Toplevel()
    window.title("Select Message")
    tree = ttk.Treeview(window, columns=("Filename",), show="tree")
    tree.heading("Filename", text="Filename")
    for filename in os.listdir(user_directory):
        tree.insert("", "end", text=filename, values=(filename,))

    tree.pack(expand=True, fill="both")

    select_button = ttk.Button(window, text="Select Message", command=select_message_to_decrypt)
    select_button.pack(pady=5)

    window.wait_window()


def load_key_rings(user):
    global public_key_ring
    global private_key_ring
    try:
        public_key_ring = public_key_ring.load_from_file(f"public_key_ring_{user}.pkl")
        private_key_ring = private_key_ring.load_from_file(f"private_key_ring_{user}.pkl")
    except FileNotFoundError:
        public_key_ring = PublicKeyRing()
        private_key_ring = PrivateKeyRing()


def show_login_window():
    def authenticate():
        global username
        global password
        username = username_entry.get()
        password = password_entry.get()

        with open("users.txt", "r") as file:
            for line in file:
                stored_username, stored_password = line.strip().split(":")
                if username == stored_username and password == stored_password:
                    load_key_rings(username)
                    root.deiconify()
                    login_window.destroy()
                    return
            messagebox.showerror("Error", "Invalid username or password")

    login_window = tk.Toplevel(root)
    login_window.title("Login")

    login_frame = ttk.Frame(login_window, padding="20")
    login_frame.grid(row=0, column=0)

    username_label = ttk.Label(login_frame, text="Username:")
    username_label.grid(row=0, column=0, padx=5, pady=5)
    username_entry = ttk.Entry(login_frame)
    username_entry.grid(row=0, column=1, padx=5, pady=5)

    password_label = ttk.Label(login_frame, text="Password:")
    password_label.grid(row=1, column=0, padx=5, pady=5)
    password_entry = ttk.Entry(login_frame, show="*")
    password_entry.grid(row=1, column=1, padx=5, pady=5)

    login_button = ttk.Button(login_frame, text="Login", command=authenticate)
    login_button.grid(row=2, columnspan=2, padx=5, pady=5, sticky="ew")


def logout():
    global username, password
    username = ""
    password = ""

    root.withdraw()
    show_login_window()


if __name__ == "__main__":
    root = tk.Tk()
    root.title("PGP")

    generate_keys_button = ttk.Button(root, text="Generate Keys", command=generate_keys_wrapper)
    generate_keys_button.pack(padx=10, pady=5, fill="x")

    generate_keys_button = ttk.Button(root, text="Load Someones Public Key", command=load_keys)
    generate_keys_button.pack(padx=10, pady=5, fill="x")

    generate_keys_button = ttk.Button(root, text="Load Pair Of Keys From File", command=load_key_pairs)
    generate_keys_button.pack(padx=10, pady=5, fill="x")

    view_public_key_ring_button = ttk.Button(root, text="View Public Key Ring", command=view_public_key_ring)
    view_public_key_ring_button.pack(padx=10, pady=5, fill="x")

    view_private_key_ring_button = ttk.Button(root, text="View Private Key Ring", command=view_private_key_ring)
    view_private_key_ring_button.pack(padx=10, pady=5, fill="x")

    send_message_button = ttk.Button(root, text="Send message", command=send_message)
    send_message_button.pack(padx=10, pady=5, fill="x")

    receive_message_button = ttk.Button(root, text="Receive message", command=receive_message)
    receive_message_button.pack(padx=10, pady=5, fill="x")

    logout_button = ttk.Button(root, text="Logout", command=logout)
    logout_button.pack(padx=10, pady=5, fill="x")

    root.withdraw()
    show_login_window()
    root.mainloop()
