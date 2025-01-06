import hashlib
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


class SignatureVerifier:
    def __init__(self):
        self.algorithms = {}
        self.register_algorithms()

    def register_algorithms(self):
        """Register supported algorithms."""
        self.algorithms = {
            "RSA": {"generate": self._generate_rsa_keys, "sign": self._rsa_sign, "verify": self._rsa_verify},
            "ECDSA": {"generate": self._generate_ecdsa_keys, "sign": self._ecdsa_sign, "verify": self._ecdsa_verify},
            "EdDSA": {"generate": self._generate_eddsa_keys, "sign": self._eddsa_sign, "verify": self._eddsa_verify},
        }

    # RSA Implementation
    def _generate_rsa_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def _rsa_sign(self, message, private_key):
        return private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def _rsa_verify(self, message, signature, public_key):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    # ECDSA Implementation
    def _generate_ecdsa_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    def _ecdsa_sign(self, message, private_key):
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def _ecdsa_verify(self, message, signature, public_key):
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    # EdDSA Implementation
    def _generate_eddsa_keys(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def _eddsa_sign(self, message, private_key):
        return private_key.sign(message)

    def _eddsa_verify(self, message, signature, public_key):
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    # Unified Interface
    def generate_keys(self, algorithm):
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return self.algorithms[algorithm]["generate"]()

    def sign_message(self, algorithm, message, private_key):
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return self.algorithms[algorithm]["sign"](message, private_key)

    def verify_signature(self, algorithm, message, signature, public_key):
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return self.algorithms[algorithm]["verify"](message, signature, public_key)


# Streamlit GUI Implementation
st.title("Digital Signature Verifier")
st.sidebar.title("Options")
verifier = SignatureVerifier()

# Initialize session state for keys and signature
if "private_key" not in st.session_state:
    st.session_state.private_key = None
if "public_key" not in st.session_state:
    st.session_state.public_key = None
if "signature" not in st.session_state:
    st.session_state.signature = None

# Select Algorithm
algorithm = st.sidebar.selectbox("Choose Algorithm", list(verifier.algorithms.keys()))

# Key Generation
st.header("Key Generation")
if st.button("Generate Keys"):
    private_key, public_key = verifier.generate_keys(algorithm)
    st.session_state.private_key = private_key
    st.session_state.public_key = public_key
    st.success("Keys Generated Successfully!")
    st.text("Private Key:")
    st.text(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
    st.text("Public Key:")
    st.text(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())

# Signing
st.header("Sign Message")
message = st.text_area("Enter Message to Sign", "")
if st.button("Sign Message"):
    if st.session_state.private_key is None:
        st.error("Please generate keys first.")
    elif not message:
        st.error("Please enter a message to sign.")
    else:
        signature = verifier.sign_message(algorithm, message.encode(), st.session_state.private_key)
        st.session_state.signature = signature
        st.success("Message Signed Successfully!")
        st.text("Signature:")
        st.text(signature.hex())

# Verification
st.header("Verify Signature")
input_signature = st.text_area("Enter Signature (Hex)", "")
if st.button("Verify Signature"):
    if st.session_state.public_key is None:
        st.error("Please generate keys first.")
    elif not input_signature:
        st.error("Please provide a signature to verify.")
    else:
        try:
            signature_bytes = bytes.fromhex(input_signature)
            is_valid = verifier.verify_signature(algorithm, message.encode(), signature_bytes, st.session_state.public_key)
            if is_valid:
                st.success("Signature Verified: Valid")
            else:
                st.error("Signature Verified: Invalid")
        except ValueError:
            st.error("Invalid signature format. Please enter a valid hex string.")
