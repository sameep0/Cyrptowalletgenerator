import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from eth_account import Account
from mnemonic import Mnemonic
import secrets
from bitcoinlib.keys import HDKey
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

BG       = "#0d0f14"
PANEL    = "#13161e"
BORDER   = "#1e2330"
ACCENT   = "#00e5ff"
ACCENT2  = "#f7931a"
TEXT     = "#e2e8f0"
TEXT_DIM = "#5a6480"
TEXT_KEY = "#a8ff78"
DANGER   = "#ff4d6d"
SUCCESS  = "#00e5a0"
BTN_BG   = "#1a1f2e"
BTN_HOV  = "#222840"

MONO    = ("Courier New", 9)
MONO_LG = ("Courier New", 10, "bold")
SANS    = ("Georgia", 10)



def derive_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def generate_ethereum_wallet() -> dict:
    private_key = "0x" + secrets.token_hex(32)
    account = Account.from_key(private_key)
    seed_phrase = Mnemonic("english").generate(strength=128)
    return {
        "chain":       "Ethereum",
        "private_key": private_key,
        "public_key":  str(account._key_obj.public_key),
        "address":     account.address,
        "seed_phrase": seed_phrase,
    }


def generate_bitcoin_wallet() -> dict:
    seed_phrase = Mnemonic("english").generate(strength=128)
    seed_bytes  = Mnemonic.to_seed(seed_phrase)
    hd_key      = HDKey.from_seed(seed_bytes, network="bitcoin")
    child       = hd_key.subkey_for_path("m/44'/0'/0'/0/0")
    return {
        "chain":       "Bitcoin",
        "private_key": child.private_hex,
        "public_key":  child.public_hex,
        "address":     child.address(encoding="base58"),
        "seed_phrase": seed_phrase,
    }


def wallet_to_text(w: dict) -> str:
    return (
        f"Chain        : {w['chain']}\n"
        f"Address      : {w['address']}\n"
        f"Public Key   : {w['public_key']}\n"
        f"Private Key  : {w['private_key']}\n"
        f"Seed Phrase  : {w['seed_phrase']}\n"
    )



class HoverButton(tk.Label):
    def __init__(self, parent, text, command, accent=ACCENT, **kw):
        super().__init__(parent, text=text, bg=BTN_BG, fg=accent,
                         font=("Georgia", 10, "bold"), padx=18, pady=10,
                         cursor="hand2", relief="flat", **kw)
        self._cmd, self._accent = command, accent
        self.bind("<Enter>",    lambda _: self.config(bg=BTN_HOV))
        self.bind("<Leave>",    lambda _: self.config(bg=BTN_BG))
        self.bind("<Button-1>", lambda _: self._cmd())


class SectionCard(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL,
                         highlightbackground=BORDER, highlightthickness=1, **kw)



class CryptoWalletGenerator:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CryptoVault — Wallet Generator")
        self.root.geometry("800x670")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        self.wallet_data = ""
        self._build_ui()

    def _build_ui(self):
        self._build_header()
        self._build_chain_selector()
        self._build_action_bar()
        self._build_output_panel()
        self._build_status_bar()

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG)
        hdr.pack(fill="x", padx=30, pady=(26, 0))
        tk.Label(hdr, text="◈  CryptoVault",
                 font=("Georgia", 20, "bold"), bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text="  Secure · Offline · Open-Source",
                 font=("Georgia", 9), bg=BG, fg=TEXT_DIM).pack(side="left", pady=(8, 0))
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(12, 0))

    def _build_chain_selector(self):
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="x", padx=30, pady=(18, 0))
        tk.Label(outer, text="SELECT NETWORK", font=("Courier New", 8, "bold"),
                 bg=BG, fg=TEXT_DIM, anchor="w").pack(fill="x", pady=(0, 8))

        row = tk.Frame(outer, bg=BG)
        row.pack(fill="x")
        self.blockchain_var = tk.StringVar(value="Ethereum")

        self.eth_card = self._chain_card(row, "Ethereum", "ETH", "EVM Compatible · BIP-39", ACCENT)
        self.eth_card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.btc_card = self._chain_card(row, "Bitcoin",  "BTC", "BIP-44 · m/44'/0'/0'/0/0", ACCENT2)
        self.btc_card.pack(side="left", fill="x", expand=True)
        self._refresh_cards()

    def _chain_card(self, parent, chain, ticker, subtitle, color):
        card = SectionCard(parent)
        card.configure(cursor="hand2")
        inner = tk.Frame(card, bg=PANEL)
        inner.pack(fill="both", padx=16, pady=14)
        tk.Label(inner, text=ticker, font=("Courier New", 24, "bold"), bg=PANEL, fg=color).pack(anchor="w")
        tk.Label(inner, text=chain,  font=("Georgia", 11, "bold"),     bg=PANEL, fg=TEXT).pack(anchor="w")
        tk.Label(inner, text=subtitle, font=("Courier New", 8),        bg=PANEL, fg=TEXT_DIM).pack(anchor="w", pady=(2,0))
        for w in [card, inner] + list(inner.winfo_children()):
            w.bind("<Button-1>", lambda _, c=chain: self._select_chain(c))
        return card

    def _select_chain(self, chain):
        self.blockchain_var.set(chain)
        self._refresh_cards()

    def _refresh_cards(self):
        sel = self.blockchain_var.get()
        self.eth_card.configure(highlightbackground=ACCENT  if sel == "Ethereum" else BORDER)
        self.btc_card.configure(highlightbackground=ACCENT2 if sel == "Bitcoin"  else BORDER)

    def _build_action_bar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=30, pady=(18, 0))
        HoverButton(bar, "⚡  Generate Wallet", self.generate_wallet).pack(side="left", padx=(0,8))
        HoverButton(bar, "🔒  Save Encrypted",  self.save_to_file).pack(side="left",   padx=(0,8))
        HoverButton(bar, "🔓  Load & Decrypt",  self.load_and_decrypt).pack(side="left",padx=(0,8))
        HoverButton(bar, "⧉  Copy All", self._copy_all, accent=TEXT_DIM).pack(side="right")

    def _build_output_panel(self):
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True, padx=30, pady=(18, 0))
        tk.Label(outer, text="WALLET OUTPUT", font=("Courier New", 8, "bold"),
                 bg=BG, fg=TEXT_DIM, anchor="w").pack(fill="x", pady=(0, 6))

        card = SectionCard(outer)
        card.pack(fill="both", expand=True)

        self.fields_frame = tk.Frame(card, bg=PANEL)
        self.fields_frame.pack(fill="both", expand=True, padx=20, pady=18)
        self.fields_frame.columnconfigure(1, weight=1)

        self._fvals = {}
        rows = [
            ("chain",       "NETWORK"),
            ("address",     "ADDRESS"),
            ("public_key",  "PUBLIC KEY"),
            ("private_key", "PRIVATE KEY"),
            ("seed_phrase", "SEED PHRASE"),
        ]
        for i, (key, label) in enumerate(rows):
            tk.Label(self.fields_frame, text=label, font=("Courier New", 8, "bold"),
                     bg=PANEL, fg=TEXT_DIM, anchor="nw", width=13
                     ).grid(row=i, column=0, sticky="nw", pady=9)

            row_height = 3 if key == "seed_phrase" else 2
            txt = tk.Text(self.fields_frame, height=row_height, wrap="word",
                          font=MONO_LG, bg=PANEL, fg=TEXT_KEY,
                          relief="flat", bd=0,
                          selectbackground=ACCENT, selectforeground=BG,
                          state="disabled", cursor="arrow")
            txt.grid(row=i, column=1, sticky="ew", pady=9, padx=(10, 0))

            cp = tk.Label(self.fields_frame, text="⧉", font=("Courier New", 10),
                          bg=PANEL, fg=TEXT_DIM, cursor="hand2", padx=6)
            cp.grid(row=i, column=2, padx=(6, 0))
            cp.bind("<Button-1>", lambda _, k=key: self._copy_field(k))
            cp.bind("<Enter>", lambda e, w=cp: w.config(fg=ACCENT))
            cp.bind("<Leave>", lambda e, w=cp: w.config(fg=TEXT_DIM))

            self._fvals[key] = txt

        # Placeholder
        self.placeholder = tk.Label(self.fields_frame,
                                    text="Generate a wallet to see your keys here.",
                                    font=("Georgia", 11, "italic"),
                                    bg=PANEL, fg=TEXT_DIM)
        self.placeholder.grid(row=0, column=0, columnspan=3, pady=60)
        self._hide_fields()

    def _hide_fields(self):
        for widget in self.fields_frame.winfo_children():
            if widget is not self.placeholder:
                widget.grid_remove()
        self.placeholder.grid()

    def _show_fields(self, wallet: dict):
        self.placeholder.grid_remove()
        for widget in self.fields_frame.winfo_children():
            if widget is not self.placeholder:
                widget.grid()
        for key, txt in self._fvals.items():
            txt.config(state="normal")
            txt.delete("1.0", "end")
            txt.insert("1.0", wallet.get(key, "—"))
            txt.config(state="disabled")

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=PANEL, height=32)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Frame(bar, bg=BORDER, height=1).place(relwidth=1)
        self.status_var = tk.StringVar(value="Ready — no wallet loaded.")
        self._status_lbl = tk.Label(bar, textvariable=self.status_var,
                                    font=("Courier New", 8), bg=PANEL, fg=TEXT_DIM,
                                    anchor="w", padx=18)
        self._status_lbl.pack(side="left", fill="y")
        tk.Label(bar, text="⚠ Never share your private key or seed phrase.",
                 font=("Courier New", 8), bg=PANEL, fg=DANGER,
                 anchor="e", padx=18).pack(side="right", fill="y")

    def _set_status(self, msg: str, color=TEXT_DIM):
        self.status_var.set(msg)
        self._status_lbl.config(fg=color)

    # ── Actions ────────────────────────────────────────────────────────────────

    def generate_wallet(self):
        chain = self.blockchain_var.get()
        try:
            wallet = generate_ethereum_wallet() if chain == "Ethereum" else generate_bitcoin_wallet()
            self.wallet_data = wallet_to_text(wallet)
            self._show_fields(wallet)
            self._set_status(f"✔  {chain} wallet generated successfully.", SUCCESS)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self._set_status(f"✖  {e}", DANGER)

    def save_to_file(self):
        if not self.wallet_data:
            messagebox.showwarning("No Wallet", "Please generate a wallet first.")
            return
        pw = simpledialog.askstring("Encrypt Wallet", "Enter a strong password:", show="*")
        if not pw:
            return
        salt = os.urandom(16)
        cipher = Fernet(derive_fernet_key(pw, salt))
        path = filedialog.asksaveasfilename(defaultextension=".enc",
                                            filetypes=[("Encrypted Wallet", "*.enc")])
        if path:
            with open(path, "wb") as f:
                f.write(salt + cipher.encrypt(self.wallet_data.encode()))
            self._set_status(f"✔  Saved → {path}", SUCCESS)
            messagebox.showinfo("Saved", f"Encrypted wallet saved:\n{path}")

    def load_and_decrypt(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted Wallet", "*.enc")])
        if not path:
            return
        pw = simpledialog.askstring("Decrypt Wallet", "Enter your password:", show="*")
        if not pw:
            return
        try:
            with open(path, "rb") as f:
                salt, enc = f.read(16), f.read()
            data = Fernet(derive_fernet_key(pw, salt)).decrypt(enc).decode()
            self.wallet_data = data
            # Parse into display dict
            field_map = {"Chain":"chain","Address":"address",
                         "Public Key":"public_key","Private Key":"private_key","Seed Phrase":"seed_phrase"}
            parsed = {}
            for line in data.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fk = field_map.get(k.strip())
                    if fk:
                        parsed[fk] = v.strip()
            self._show_fields(parsed)
            self._set_status(f"✔  Wallet decrypted from {path}", SUCCESS)
            messagebox.showinfo("Success", "Wallet loaded successfully!")
        except InvalidToken:
            messagebox.showerror("Wrong Password", "Incorrect password or corrupted file.")
            self._set_status("✖  Decryption failed.", DANGER)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self._set_status(f"✖  {e}", DANGER)

    def _copy_field(self, key: str):
        txt = self._fvals.get(key)
        if txt:
            val = txt.get("1.0", "end").strip()
            if val and val != "—":
                self.root.clipboard_clear()
                self.root.clipboard_append(val)
                self._set_status(f"⧉  {key.replace('_',' ').title()} copied.", ACCENT)

    def _copy_all(self):
        if self.wallet_data:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.wallet_data)
            self._set_status("⧉  All wallet data copied to clipboard.", ACCENT)
        else:
            messagebox.showwarning("No Wallet", "Generate a wallet first.")


if __name__ == "__main__":
    root = tk.Tk()
    CryptoWalletGenerator(root)
    root.mainloop()