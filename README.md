# InMemoryVault 🔒

A high-security, lightweight Flask web application designed to encrypt and decrypt text files instantly in system memory. Because data passes entirely through RAM, **nothing is ever written to the server's hard drive**, ensuring zero residual footprint.

## 🚀 Key Features
* **In-Memory Streams:** Uses Python's `io.BytesIO` to read and process file chunks purely in volatile memory.
* **Brute-Force Resistance:** Uses **PBKDF2HMAC** (SHA-256) running 480,000 hashing iterations to derive cryptographic keys from user passwords.
* **AES-256 Bit Encryption:** Built on top of the robust, production-grade `cryptography.fernet` engine.
* **Modern Interface:** Styled with a responsive, dark-mode layout powered by Tailwind CSS.

---

## 🛠️ Installation & Local Setup

### 1. Clone the repository
```bash
git clone [https://github.com/plainvector-art/flask-crypto-app.git](https://github.com/plainvector-art/flask-crypto-app.git)
cd flask-crypto-app