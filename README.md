
# **SignatureVerifier**

A robust digital signature generation and verification tool built with Python and Streamlit. This project demonstrates the use of various cryptographic algorithms for signing and verifying messages, including RSA, ECDSA, and EdDSA, with a simple and interactive graphical user interface.

You can try it out at : [Link](https://signatureverifier.streamlit.app/)

## **Features**
- **Key Pair Generation**:
  - Generate public-private key pairs using supported algorithms: RSA, ECDSA, and EdDSA.
- **Message Signing**:
  - Sign messages securely with private keys using the selected algorithm.
- **Signature Verification**:
  - Verify signatures using the corresponding public keys.
- **Interactive GUI**:
  - User-friendly interface powered by Streamlit for all operations.
- **Supports Multiple Algorithms**:
  - RSA (2048-bit keys)
  - ECDSA (Elliptic Curve Digital Signature Algorithm using SECP256R1 curve)
  - EdDSA (Ed25519 keys for high-speed signature operations)

---

## **Installation**

### **1. Clone the Repository**
```bash
git clone https://github.com/RohanSai22/SignatureVerifier
cd SignatureVerifier
```

### **2. Set Up a Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### **3. Install Dependencies**
```bash
pip install -r requirements.txt
```

---

## **Usage**

### **Run the Application**
```bash
streamlit run streamlit_app.py
```

### **Steps to Use**
1. **Select Algorithm**:
   - Choose your desired algorithm (RSA, ECDSA, or EdDSA) from the sidebar.
2. **Generate Keys**:
   - Click on the "Generate Keys" button to create a public-private key pair.
   - View the PEM-formatted keys in the interface.
3. **Sign a Message**:
   - Enter a message in the "Sign Message" section.
   - Click "Sign Message" to generate a signature for the input message.
   - Copy the signature for verification.
4. **Verify a Signature**:
   - Paste the generated signature or provide a custom one in the "Verify Signature" section.
   - Click "Verify Signature" to check the validity of the signature against the input message.

---

## **Technologies Used**
- **Cryptography**:
  - Python's `cryptography` library is used for cryptographic operations, including key generation, signing, and verification.
- **Streamlit**:
  - Provides the interactive GUI for key generation, signing, and verification.
- **Python**:
  - Core programming language for implementing the project.

---

## **Example Workflow**

1. **Key Generation**:
   - Select "RSA" from the sidebar.
   - Click "Generate Keys".
   - Copy the displayed keys for backup or further use.

2. **Message Signing**:
   - Input message: `"Hello, Digital Signature!"`.
   - Click "Sign Message".
   - The application will display the hexadecimal-encoded signature.

3. **Signature Verification**:
   - Paste the signature into the "Verify Signature" section.
   - Click "Verify Signature".
   - The application confirms if the signature is valid or not.

---

## **Project Structure**

```
SignatureVerifier/
├── streamlit_app.py       # Main application file
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
```

---

## **Dependencies**
Ensure the following Python packages are installed:
- `streamlit`
- `cryptography`

Install them via:
```bash
pip install -r requirements.txt
```

---

## **Advantages**
- **Security**:
  - Employs industry-standard cryptographic practices.
- **Flexibility**:
  - Supports multiple signature algorithms for various use cases.
- **Simplicity**:
  - Interactive GUI for ease of use.
- **Educational**:
  - Demonstrates the concepts of digital signatures, making it useful for learning purposes.

---

## **Limitations**
- **Not for Production**:
  - This project is a learning tool and not optimized for real-world production environments.
- **Limited Algorithm Choices**:
  - Currently supports RSA, ECDSA, and EdDSA; additional algorithms can be integrated.

---

## **Future Enhancements**
- Add support for more cryptographic algorithms like DSA or post-quantum algorithms.
- Enhance the GUI with advanced features like key upload/download.
- Provide detailed logs for each operation.

---

## **License**
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## **Contributing**
Contributions are welcome! Feel free to fork the repository and submit pull requests.

---

## **Contact**
For any queries or issues, contact:
- **Name**: Rohan Sai
- **Email**: maragonoirohansai@gmail.com

