import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk  # pip install pillow
from Crypto.Cipher import AES     # pip install pycryptodome
from Crypto.Random import get_random_bytes
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, NIST256p # pip install ecdsa

# =========================
# AES-GCM ENCRYPTION / DECRYPTION
# =========================
def aes_gcm_encrypt(data: bytes, key: bytes):
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return iv, ciphertext, tag

def aes_gcm_decrypt(iv: bytes, ciphertext: bytes, tag: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

# =========================
# PDF + SIGNATURE HANDLING
# =========================
def create_keys():
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()
    return sk, vk

def encrypt_and_sign_pdf(pdf_path: str, aes_key: bytes, sk: SigningKey):
    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    iv, ciphertext, tag = aes_gcm_encrypt(pdf_data, aes_key)

    # SHA-256 hash of ciphertext
    hash_digest = sha256(ciphertext).digest()

    # Sign hash
    signature = sk.sign(hash_digest)

    # Save encrypted PDF
    encrypted_pdf = pdf_path.replace(".pdf", "_encrypted.pdf")
    with open(encrypted_pdf, "wb") as f:
        f.write(iv + tag + ciphertext)

    # Return all values as per your logic
    return encrypted_pdf, iv, tag, ciphertext, signature, sk, sk.get_verifying_key()

def verify_and_decrypt_pdf(encrypted_pdf_path: str, aes_key: bytes, vk: VerifyingKey, signature: bytes):
    with open(encrypted_pdf_path, "rb") as f:
        raw = f.read()

    iv = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]

    hash_digest = sha256(ciphertext).digest()
    if not vk.verify(signature, hash_digest):
        raise ValueError("Signature invalide !")

    plaintext = aes_gcm_decrypt(iv, ciphertext, tag, aes_key)

    decrypted_pdf = encrypted_pdf_path.replace(".pdf", "_decrypted.pdf")
    with open(decrypted_pdf, "wb") as f:
        f.write(plaintext)

    return decrypted_pdf

# =========================
# GUI CONSTANTS
# =========================
LABEL_FONT = ("Segoe UI", 12)
TITLE_FONT = ("Segoe UI", 24, "bold")
BUTTON_FONT = ("Segoe UI", 11, "bold")
ENTRY_FONT = ("Consolas", 11)
STATUS_FONT = ("Segoe UI", 11, "italic")

def apply_fullscreen_theme(root):
    root.configure(bg="#0b0b0b")
    root.attributes("-fullscreen", True)
    root.bind("<Escape>", lambda e: root.attributes("-fullscreen", False))

# =========================
# TKINTER CANVAS GUI
# =========================
class PDFSecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure PDF Encryption & Digital Signature")
        
        # Get Screen Dimensions
        self.sw = root.winfo_screenwidth()
        self.sh = root.winfo_screenheight()

        # 1. SETUP CANVAS (The main container)
        self.canvas = tk.Canvas(root, highlightthickness=0, bg="#0b0b0b")
        self.canvas.pack(fill="both", expand=True)

        # 2. LOAD BACKGROUND WALLPAPER
        # Make sure "image cyber.jpg" is in the same folder
        self.bg_filename = "image cyber.jpg" 
        self.load_background()

        # 3. DRAW TRANSPARENT PANEL
        # Alpha=150 (Transparent), No Outline
        self.draw_transparent_panel(width=900, height=650, alpha=150)

        # VARIABLES
        self.pdf_path = tk.StringVar()
        
        # 4. UI ELEMENTS
        cx = self.sw // 2
        cy = self.sh // 2
        
        # -- Title --
        self.canvas.create_text(cx, cy - 250, text="SECURE PDF ENCRYPTION", 
                                font=TITLE_FONT, fill="#ff4d4d")

        # -- File Selection --
        self.canvas.create_text(cx - 280, cy - 180, text="PDF File:", 
                                font=LABEL_FONT, fill="#ff4d4d", anchor="e")
        
        self.path_entry = tk.Entry(root, textvariable=self.pdf_path, width=45, 
                                   font=ENTRY_FONT, bg="#1a1a1a", fg="#ff4d4d", 
                                   insertbackground="#ff4d4d", relief="flat")
        self.canvas.create_window(cx, cy - 180, window=self.path_entry)

        btn_browse = tk.Button(root, text="BROWSE", command=self.browse_pdf, 
                               bg="#b91c1c", fg="white", font=BUTTON_FONT, 
                               relief="flat", cursor="hand2")
        self.canvas.create_window(cx + 280, cy - 180, window=btn_browse)

        # -- Action Buttons --
        btn_encrypt = tk.Button(root, text="ENCRYPT & SIGN", command=self.encrypt_pdf, 
                                bg="#b91c1c", fg="white", font=BUTTON_FONT, 
                                relief="flat", cursor="hand2", width=18)
        self.canvas.create_window(cx - 100, cy - 110, window=btn_encrypt)

        btn_decrypt = tk.Button(root, text="VERIFY & DECRYPT", command=self.decrypt_pdf, 
                                bg="#b91c1c", fg="white", font=BUTTON_FONT, 
                                relief="flat", cursor="hand2", width=18)
        self.canvas.create_window(cx + 100, cy - 110, window=btn_decrypt)

        # -- Output Fields --
        self.aes_key_entry = self.create_output_row(cx, cy - 20, "AES Key (Base64)")
        self.pub_key_entry = self.create_output_row(cx, cy + 50, "Public Key (PEM)")
        self.signature_entry = self.create_output_row(cx, cy + 120, "Signature (Base64)")

        # -- Status --
        self.status_item = self.canvas.create_text(cx, cy + 200, text="System Ready", 
                                                   font=STATUS_FONT, fill="#ff4d4d")

        # -- Exit Hint --
        self.canvas.create_text(cx, self.sh - 30, text="Press ESC to exit fullscreen", 
                                font=("Segoe UI", 9), fill="white")

    def load_background(self):
        try:
            original_image = Image.open(self.bg_filename)
            resized_image = original_image.resize((self.sw, self.sh), Image.Resampling.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(resized_image)
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw", tag="bg")
        except Exception as e:
            print(f"Error loading background: {e}")
            self.canvas.configure(bg="#0b0b0b")

    def draw_transparent_panel(self, width, height, alpha):
        # Create semi-transparent black image (RGBA)
        self.panel_image = Image.new('RGBA', (width, height), (0, 0, 0, alpha))
        self.panel_photo = ImageTk.PhotoImage(self.panel_image)
        self.canvas.create_image(self.sw//2, self.sh//2, image=self.panel_photo)
        
        # Border (Commented out as requested)
        # x1 = (self.sw - width) // 2
        # y1 = (self.sh - height) // 2
        # self.canvas.create_rectangle(x1, y1, x1+width, y1+height, outline="#ff4d4d", width=2)

    def create_output_row(self, center_x, y_pos, label_text):
        self.canvas.create_text(center_x - 300, y_pos, text=label_text, 
                                font=LABEL_FONT, fill="#ff4d4d", anchor="e")
        entry = tk.Entry(self.root, width=60, font=ENTRY_FONT, bg="#1a1a1a", 
                         fg="#ff4d4d", insertbackground="#ff4d4d", relief="flat")
        self.canvas.create_window(center_x + 50, y_pos, window=entry)
        return entry

    def update_status(self, message):
        self.canvas.itemconfig(self.status_item, text=message)

    # =========================
    # APP LOGIC
    # =========================
    def browse_pdf(self):
        path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if path:
            self.pdf_path.set(path)

    def encrypt_pdf(self):
        try:
            if not self.pdf_path.get():
                raise ValueError("Please select a PDF file first.")
            
            # 1. Generate keys
            aes_key = get_random_bytes(32)
            sk, vk = create_keys()
            
            # 2. Call your logic function
            # Note: We ignore iv, tag, ciphertext here as they are written to file
            _, _, _, _, signature, _, _ = encrypt_and_sign_pdf(self.pdf_path.get(), aes_key, sk)

            # 3. Update UI
            self.aes_key_entry.delete(0, tk.END)
            self.aes_key_entry.insert(0, base64.b64encode(aes_key).decode())
            
            self.pub_key_entry.delete(0, tk.END)
            self.pub_key_entry.insert(0, vk.to_pem().decode())
            
            self.signature_entry.delete(0, tk.END)
            self.signature_entry.insert(0, base64.b64encode(signature).decode())

            self.update_status("SUCCESS: PDF encrypted and signed.")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_pdf(self):
        try:
            # 1. Retrieve keys from UI
            aes_key = base64.b64decode(self.aes_key_entry.get())
            vk = VerifyingKey.from_pem(self.pub_key_entry.get().encode())
            signature = base64.b64decode(self.signature_entry.get())

            # 2. Verify and Decrypt
            verify_and_decrypt_pdf(self.pdf_path.get(), aes_key, vk, signature)
            self.update_status("SUCCESS: Signature verified and PDF decrypted.")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    apply_fullscreen_theme(root)
    app = PDFSecureApp(root)
    root.mainloop()