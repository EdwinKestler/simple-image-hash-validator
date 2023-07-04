import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

# Global variable to hold the current file path
current_file_path = None

def calculate_hash(file_path):
    """
    Calculate the hash of a file using SHA256 algorithm.
    """
    hash_object = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_object.update(chunk)
    return hash_object.hexdigest()

def is_valid_sha256(s):
    """
    Prevalidate a hash by checking if it is a string of exactly 64 characters,
    and every character is a valid hexadecimal character.
    """
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def validate_hash(*args):
    """
    Check if the hash value entered in the GUI is valid or not,
    and display a check or cross image accordingly.
    """
    hash_value = hash_entry.get()
    if is_valid_sha256(hash_value):
        image = Image.open("minihashvalid.png")
        hash_status_label.configure(text="el valor hash es valido")
    else:
        image = Image.open("minihashinvalid.png")
        hash_status_label.configure(text="el valor hash no es invalido")
    photo = ImageTk.PhotoImage(image)
    hash_check_label.configure(image=photo)
    hash_check_label.image = photo

def validate_image_hash():
    """
    Validate the hash of the current preview image against the expected hash value.
    """
    global current_file_path
    if not current_file_path:
        messagebox.showerror("Error", "Please select an image to preview before validation.")
        return

    expected_hash = hash_entry.get()
    if not expected_hash:
        messagebox.showerror("Error", "Please enter the expected hash value.")
        return

    image_hash = calculate_hash(current_file_path)
    if image_hash == expected_hash:
        messagebox.showinfo("Validation Result", "Image hash is valid.")
    else:
        messagebox.showerror("Validation Result", "Image hash is not valid.")

def show_preview():
    """
    Display the selected image in the GUI window.
    """
    global current_file_path
    current_file_path = filedialog.askopenfilename(title="Select an image file", filetypes=[("JPEG files", "*.jpg")])
    if current_file_path:
        image = Image.open(current_file_path)
        image.thumbnail((400, 600))  # Resize the image to fit in the GUI window
        photo = ImageTk.PhotoImage(image)
        preview_label.configure(image=photo)
        preview_label.image = photo

def close_program():
    """
    Close the GUI window and exit the program.
    """
    window.destroy()

# Create the GUI window
window = tk.Tk()
window.title("Image Hash Validator")
window.geometry("480x800")  # Set the window size to 480x800 pixels

# Create widgets
label = tk.Label(window, text="Enter the expected hash value:")
label.pack()

hash_value = tk.StringVar()
hash_value.trace("w", validate_hash)
hash_entry = tk.Entry(window, textvariable=hash_value)
hash_entry.pack()

hash_check_label = tk.Label(window)
hash_check_label.pack(side=tk.BOTTOM)  # Pack the icon to the side of the hash entry

hash_status_label = tk.Label(window, text="")
hash_status_label.pack(side=tk.BOTTOM)  # Pack the status label to the side of the icon

preview_button = tk.Button(window, text="Preview", command=show_preview)
preview_button.pack()

preview_label = tk.Label(window)
preview_label.pack()

validate_button = tk.Button(window, text="Validate", command=validate_image_hash)
validate_button.pack()

close_button = tk.Button(window, text="Close", command=close_program)
close_button.pack()

# Run the GUI event loop
window.mainloop()