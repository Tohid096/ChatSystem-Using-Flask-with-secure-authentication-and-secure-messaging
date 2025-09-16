# 🔐 Encrypted Messaging App — Flask End-to-End Encrypted Chat

> A fully functional, end-to-end encrypted messaging web application built with Flask. Messages are encrypted on the sender’s device and can only be decrypted by the recipient using their password.

---

## 🌟 Features

- ✅ **End-to-End Encryption** — Server never sees plaintext messages
- ✅ User Registration & Login with password hashing
- ✅ Send encrypted messages to other users
- ✅ Decrypt messages using recipient’s own password
- ✅ Message read/unread status
- ✅ Delete messages
- ✅ Responsive UI with Bootstrap
- ✅ SQLite database (easily swappable)
- ✅ CSRF protection via Flask-WTF
- ✅ Session management via Flask-Login

---

## ⚠️ Important Security Note

This app uses **symmetric encryption based on user passwords**:

- To send a message to Bob, Alice must know **Bob’s password** to encrypt it.
- Bob decrypts it using **his own password**.
- This is a **simplified educational model** — not ideal for production.

> 🚀 **Production Recommendation**: Use **asymmetric (public-key) encryption** (e.g., RSA or ECC) so senders don’t need recipients’ passwords. *(Upgrade guide available — ask me!)*

---

## 🛠️ Technical Stack

| Component       | Technology             |
|----------------|------------------------|
| Backend        | Python Flask           |
| Database       | SQLite (via SQLAlchemy)|
| Authentication | Flask-Login            |
| Forms          | Flask-WTF              |
| Encryption     | `cryptography` (Fernet + PBKDF2) |
| Frontend       | Bootstrap 5 + Jinja2   |
| Environment    | python-dotenv          |

---

## 📦 Installation & Setup

### 1. Clone or Create Project

If starting fresh:

```bash
mkdir encrypted-messaging-app
cd encrypted-messaging-app
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv
source venv/bin/activate      # Linux/macOS
# OR
venv\Scripts\activate         # Windows
```

### 3. Install Dependencies

```bash
pip install flask flask-sqlalchemy flask-login flask-wtf email-validator cryptography python-dotenv
```

### 4. Create `.env` File

Create `.env` in the root folder:

```env
SECRET_KEY=your_super_secret_key_change_this_in_production
DATABASE_URL=sqlite:///messages.db
```

> 🔐 **Never commit `.env` to version control!**

---

## 📁 Project Structure

```
encrypted-messaging-app/
├── .env
├── app.py
├── models.py
├── routes.py
├── forms.py
├── templates/
│   ├── base.html
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── send_message.html
│   └── view_message.html
└── venv/
```

---

## ▶️ Running the App

From your project root:

```bash
python app.py
```

Visit: 👉 [http://localhost:5000](http://localhost:5000)

---

## 🧭 Step-by-Step Usage Guide

### ✅ Step 1: Register Two Users

1. Go to **Register** page
2. Create account for **Alice**:
   - Username: `alice`
   - Email: `alice@example.com`
   - Password: `password123`
3. Create account for **Bob**:
   - Username: `bob`
   - Email: `bob@example.com`
   - Password: `secret456`

---

### ✅ Step 2: Log In as Alice

1. Go to **Login**
2. Enter Alice’s email and password
3. You’ll be redirected to **Dashboard**

---

### ✅ Step 3: Send Encrypted Message to Bob

1. Click **Send Message**
2. Fill in:
   - Recipient Username: `bob`
   - Message: `Hello Bob! This is a secret message.`
3. Click **Send Encrypted Message**
4. 👉 You’ll be prompted: **“Enter recipient’s password to encrypt the message”**
5. Enter Bob’s password: `secret456`
6. Click **Send Encrypted Message** again
7. ✅ Success! Message sent.

---

### ✅ Step 4: Log In as Bob

1. Click **Logout**
2. Log in with Bob’s credentials
3. Go to **Dashboard**
4. You’ll see a new message from Alice (marked **“New”**)

---

### ✅ Step 5: Decrypt and Read Message

1. Click on the message from Alice
2. You’ll see encrypted gibberish (e.g., `gAAAAABm...`)
3. Enter **your own password** (`secret456`) in the “Your Password” field
4. Click **Decrypt Message**
5. ✅ Voilà! You see: `Hello Bob! This is a secret message.`

---

### ✅ Step 6: Reply to Alice

1. Click **Send Message**
2. Recipient: `alice`
3. Message: `Hi Alice! Got your message.`
4. Enter Alice’s password: `password123`
5. Send → Log out → Log in as Alice → Decrypt with her password

---

## 🔄 Message Flow Summary

| Step | Action | Who | Notes |
|------|--------|-----|-------|
| 1 | Compose Message | Alice | Types plaintext |
| 2 | Enter Recipient’s Password | Alice | `secret456` (Bob’s) |
| 3 | Encrypt | System | Uses Bob’s salt + Bob’s password |
| 4 | Store Encrypted | Database | Only ciphertext saved |
| 5 | Decrypt | Bob | Uses his own password (`secret456`) |
| 6 | Display Plaintext | Bob | Only on his browser |

---

## 🧪 Testing Notes

- Try sending to non-existent user → error
- Try sending to yourself → blocked
- Change password → old messages can’t be decrypted (by design)
- Delete message → removed from DB

---

## 🛡️ Security Architecture

### 🔑 Key Derivation

```python
PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=user.salt,
    iterations=100000
)
```

→ Produces deterministic key from password + unique salt.

### 🔐 Encryption

- Uses `Fernet` (symmetric authenticated encryption)
- Based on AES-128-CBC + HMAC-SHA256
- URL-safe Base64 encoding

### 🧑‍💻 Authentication

- Flask-Login for session management
- Passwords hashed with Werkzeug’s `generate_password_hash`
- Each user has unique salt

---

## 🚀 Production Improvements (Recommended)

| Feature | Why | Status |
|---------|-----|--------|
| HTTPS | Prevent MITM | ❌ Not implemented |
| Rate Limiting | Prevent brute force | ❌ |
| Public-Key Encryption | No password sharing | ❌ *(Ask for upgrade!)* |
| Master Key System | Change password without losing messages | ❌ |
| 2FA | Extra login security | ❌ |
| Message Expiry | Auto-delete | ❌ |
| Audit Logs | Track access | ❌ |

---

## ❓ FAQ

### ❓ Why do I need the recipient’s password to send a message?

> This is a **simplified symmetric model** for learning. In real apps (Signal, WhatsApp), you’d use the recipient’s **public key** to encrypt — no password needed.

### ❓ What if I forget my password?

> ❗ **All your encrypted messages are permanently lost.** This is by design in true end-to-end encryption. No backdoors.

### ❓ Can the server read my messages?

> ❌ **No.** The server only stores encrypted blobs. Decryption happens in the browser after you enter your password.

### ❓ Can I decrypt messages I sent?

> ❌ **No** — because you encrypted them with the *recipient’s* key. Only the recipient can decrypt.

---

## 🧑‍💻 Developer Notes

### To Reset Everything

Delete:
- `messages.db`
- Restart app → `python app.py` → tables recreated

### To Change Encryption

See `models.py` → `derive_key_from_password()` and `get_encryption_key()`

### To Upgrade to RSA (Public-Key)

Ask me for the RSA implementation — it replaces password-sharing with public-key crypto.

---

## 📄 License

MIT License — Use freely for learning and personal projects.

---

## 🙋‍♂️ Need Help?

Found a bug? Want RSA encryption? Need deployment help?

→ Ask me! I’m here to help you build the most secure version possible.

---

✅ **You’re ready to start sending encrypted messages!**

> http://localhost:5000

🔐 **Remember: With great encryption comes great responsibility. Keep those passwords safe!**

---

> 💡 **Pro Tip**: Bookmark this README — it’s your operational manual for the app!

---

Let me know if you want:
- Docker setup
- PostgreSQL migration
- User profile pictures
- Group messaging
- Real-time updates with Socket.IO
- Mobile-friendly PWA version

Happy encrypted messaging! 💌🔐
