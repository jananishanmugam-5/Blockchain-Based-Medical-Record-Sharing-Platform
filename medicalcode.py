import os
import json
import hashlib
import time
import csv
import shutil
import difflib
import sqlite3
import base64
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from PIL import Image
import numpy as np

# ================== BASIC SETUP ==================
ROOT_PATH = "network"
FOLDERS = [str(i) for i in range(1, 101)]
DB_FILE = "hospital_auth.db"

for f in FOLDERS:
    os.makedirs(os.path.join(ROOT_PATH, f), exist_ok=True)

# ================== BLOCKCHAIN ==================
class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.new_block(100, "1")

    def new_block(self, proof, previous_hash):
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "transactions": self.pending_transactions,
            "proof": proof,
            "previous_hash": previous_hash
        }
        self.pending_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, hospital, pid, doctor, pname, dosage):
        self.pending_transactions.append({
            "hospital": hospital,
            "patient_id": pid,
            "doctor": doctor,
            "patient_name": pname,
            "dosage": dosage
        })

    def hash(self, block):
        return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

    def proof_of_work(self, last_proof):
        proof = 0
        while True:
            guess = f"{last_proof}{proof}".encode()
            if hashlib.sha256(guess).hexdigest()[:4] == "0000":
                return proof
            proof += 1

    @property
    def last_block(self):
        return self.chain[-1]

# ================== DATABASE ==================
def get_connection():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS hospitals
              (username TEXT PRIMARY KEY, password TEXT)""")
    conn.commit()
    return conn

def register_hospital(username, password):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM hospitals WHERE username=?", (username,))
    if c.fetchone():
        return False
    c.execute("INSERT INTO hospitals VALUES (?,?)", (username, password))
    conn.commit()
    conn.close()

    for f in FOLDERS:
        path = os.path.join(ROOT_PATH, f, f"{username}.csv")
        if not os.path.exists(path):
            with open(path, "w", newline="") as file:
                csv.writer(file).writerow(
                    ["block_index", "prev_hash", "record_index", "tx"]
                )
    return True

def login(username, password):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT password FROM hospitals WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row and row[0] == password

# ================== CSV FUNCTIONS ==================
def save_record(username, record):
    for f in FOLDERS:
        with open(os.path.join(ROOT_PATH, f, f"{username}.csv"), "a", newline="") as file:
            csv.writer(file).writerow(record)

def load_records(username):
    path = os.path.join(ROOT_PATH, "1", f"{username}.csv")
    if not os.path.exists(path):
        return []
    records = []
    with open(path) as file:
        reader = csv.reader(file)
        next(reader)
        for r in reader:
            records.append((int(r[0]), r[1], int(r[2]), json.loads(r[3])))
    return records

# ================== TAMPER DETECTION ==================
def detect_tampering(username):
    contents = []
    for f in FOLDERS:
        p = os.path.join(ROOT_PATH, f, f"{username}.csv")
        contents.append(open(p).read() if os.path.exists(p) else "")
    diffs = []
    for i, c1 in enumerate(contents):
        diff = sum(1 - difflib.SequenceMatcher(None, c1, c2).ratio()
                   for c2 in contents)
        diffs.append((FOLDERS[i], diff))
    diffs.sort(key=lambda x: x[1])
    return diffs[-1][1] > 0.3, diffs[0][0]

# ================== STEGANOGRAPHY ==================
def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)

def embed_text(image, text):
    img = image.convert("RGB")
    data = np.array(img)
    binary = text_to_binary(text) + "1111111111111110"
    flat = data.flatten()

    if len(binary) > len(flat):
        raise ValueError("Data too large")

    for i in range(len(binary)):
        flat[i] = (flat[i] & 254) | int(binary[i])

    return Image.fromarray(flat.reshape(data.shape))

def extract_text(image):
    img = image.convert("RGB")
    flat = np.array(img).flatten()
    binary = ""
    for v in flat:
        binary += str(v & 1)
        if binary.endswith("1111111111111110"):
            break
    return binary_to_text(binary.replace("1111111111111110", ""))

# ================== STREAMLIT UI ==================
st.set_page_config("Secure Patient System")

# ---------- BACKGROUND IMAGE (BASE64 ENCODED, NO OVERLAY) ----------
def get_base64_of_image(image_path):
    try:
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode()
    except FileNotFoundError:
        return None

image_path = "background.jpeg"  # or "background.jpg" etc.
base64_image = get_base64_of_image(image_path)

if base64_image:
    background_style = f"""
    <style>
    .stApp {{
        background: url('data:image/jpeg;base64,{base64_image}');
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
    }}
    </style>
    """
else:
    background_style = """
    <style>
    .stApp {
        background-color: #e6f3ff;
    }
    </style>
    """

st.markdown(background_style, unsafe_allow_html=True)
# --------------------------------------------------------

if "bc" not in st.session_state:
    st.session_state.bc = Blockchain()

if "logged" not in st.session_state:
    st.session_state.logged = False

if not st.session_state.logged:
    st.title("🏥 Hospital Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        if login(u, p):
            st.session_state.logged = True
            st.session_state.user = u
            st.rerun()
        else:
            st.error("Invalid credentials")

    if st.button("Register"):
        if register_hospital(u, p):
            st.success("Registered successfully")
        else:
            st.error("Already exists")

else:
    st.title(f"Welcome {st.session_state.user}")

    menu = st.selectbox("Menu", [
        "Add Patient",
        "View Records",
        "Detect Tampering",
        "Steganography: Embed",
        "Steganography: Retrieve",
        "Logout"
    ])

    # ADD PATIENT
    if menu == "Add Patient":
        pid = st.text_input("Patient ID")
        doc = st.text_input("Doctor")
        name = st.text_input("Patient Name")
        dose = st.text_area("Dosage")

        if st.button("Save"):
            bc = st.session_state.bc
            proof = bc.proof_of_work(bc.last_block["proof"])
            bc.new_transaction(st.session_state.user, pid, doc, name, dose)
            block = bc.new_block(proof, bc.hash(bc.last_block))
            record = [block["index"], block["previous_hash"], len(bc.chain),
                      json.dumps({"patient_id": pid, "doctor": doc,
                                  "patient_name": name, "dosage": dose})]
            save_record(st.session_state.user, record)
            st.success("Saved to Blockchain & Network")

    # VIEW
    elif menu == "View Records":
        recs = load_records(st.session_state.user)
        if recs:
            df = pd.DataFrame([r[3] for r in recs])
            st.dataframe(df)
        else:
            st.info("No records")

    # TAMPER
    elif menu == "Detect Tampering":
        tampered, source = detect_tampering(st.session_state.user)
        if tampered:
            st.error("Tampering detected!")
            if st.button("Restore"):
                src = os.path.join(ROOT_PATH, source, f"{st.session_state.user}.csv")
                for f in FOLDERS:
                    dst = os.path.join(ROOT_PATH, f, f"{st.session_state.user}.csv")
                    if os.path.abspath(src) == os.path.abspath(dst):
                        continue
                    shutil.copy(src, dst)
                st.success("Restored successfully across network")
        else:
            st.success("No tampering detected")

    # STEGO EMBED
    elif menu == "Steganography: Embed":
        recs = load_records(st.session_state.user)
        if not recs:
            st.warning("No records")
        else:
            pid = st.selectbox("Select Patient", [r[3]["patient_id"] for r in recs])
            rec = next(r for r in recs if r[3]["patient_id"] == pid)
            img = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
            if img and st.button("Embed"):
                stego = embed_text(Image.open(img), json.dumps(rec[3]))
                stego.save(f"stego_{pid}.png")
                st.image(stego)
                st.success("Data embedded & saved")

    # STEGO RETRIEVE
    elif menu == "Steganography: Retrieve":
        img = st.file_uploader("Upload Stego Image", type=["png", "jpg", "jpeg"])
        if img and st.button("Extract"):
            try:
                data = json.loads(extract_text(Image.open(img)))
                st.json(data)
            except:
                st.error("No hidden data found")

    elif menu == "Logout":
        st.session_state.logged = False
        st.rerun()