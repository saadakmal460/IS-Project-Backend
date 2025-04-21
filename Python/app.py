from flask import Flask, request, jsonify
from flask_cors import CORS
from transformers import pipeline, AutoTokenizer
import pdfplumber
import os
import re
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tempfile
import requests
from dotenv import load_dotenv

# Configs
MAX_TEXT_LENGTH = 10000000
MAX_SUMMARY_LENGTH = 480
MIN_SUMMARY_LENGTH = 50
ALLOWED_EXTENSIONS = {'pdf', 'txt'}
TEMP_DIR = "temp"
MAX_INPUT_TOKENS = 1024

# App and Summarizer
app = Flask(__name__)
CORS(app)
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
tokenizer = AutoTokenizer.from_pretrained("facebook/bart-large-cnn")

# RSA Keypair (generate once on startup)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def get_public_pem():
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

@app.route("/public-key", methods=["GET"])
def serve_public_key():
    return get_public_pem().decode(), 200

def is_valid_file_extension(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path, file_extension):
    try:
        if file_extension == 'pdf':
            with pdfplumber.open(file_path) as pdf_document:
                return " ".join(page.extract_text() or "" for page in pdf_document.pages).strip()
        else:
            with open(file_path, 'r', encoding='utf-8') as text_file:
                return text_file.read().strip()
    except Exception as error:
        raise ValueError(f"Error extracting text: {str(error)}")

def clean_text(text):
    lines = text.splitlines()
    unique_lines = []
    seen = set()

    for line in lines:
        clean_line = line.strip()
        if clean_line and clean_line not in seen:
            seen.add(clean_line)
            unique_lines.append(clean_line)

    text = " ".join(unique_lines)
    text = re.sub(r"\b(Entity|LIMITED|Session:.*?2026)\b", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()

def chunk_text_by_sentences(text, max_tokens):
    sentences = re.split(r'(?<=\.)\s+', text)
    chunks = []
    current_chunk = ""
    current_tokens = 0

    for sentence in sentences:
        tokens = tokenizer(sentence, return_tensors="pt", truncation=False)["input_ids"][0]
        token_count = len(tokens)

        if current_tokens + token_count > max_tokens:
            if current_chunk:
                chunks.append(current_chunk)
            current_chunk = sentence
            current_tokens = token_count
        else:
            current_chunk = f"{current_chunk} {sentence}" if current_chunk else sentence
            current_tokens += token_count

    if current_chunk:
        chunks.append(current_chunk)

    return chunks

def decrypt_aes_gcm(ciphertext, key, iv, auth_tag):
    """
    Decrypts the ciphertext using AES-GCM with the provided key, IV, and authentication tag.
    """
    try:
        # Ensure the auth_tag is correctly passed as a byte string (16 bytes)
        if len(auth_tag) != 16:
            raise ValueError("Authentication tag must be 16 bytes.")
        
        # Create AES-GCM cipher instance with the provided key, IV, and authentication tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext and return the result
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data

    except Exception as e:
        print(f"Error in AES-GCM decryption: {e}")
        raise

@app.route("/summarize", methods=["POST"])
def summarize_document():
    try:
        captcha_token = request.form.get("captcha_token")
        if not captcha_token:
            return jsonify({"error": "Captcha token is missing."}), 400

        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        secret_key = os.environ.get("RECAPTCHA_SECRET_KEY")  # store in .env or env var

        response = requests.post(verify_url, data={
            "secret": secret_key,
            "response": captcha_token
        })
        result = response.json()


        if not result.get("success"):
            return jsonify({"error": "Failed CAPTCHA verification."}), 403
        
        
        # Get the file, key, IV, and auth_tag from the request
        enc_file = request.files["file"].read()
        encrypted_key = request.files["key"].read()
        encrypted_iv = request.files["iv"].read()
        auth_tag = request.files["auth_tag"].read()

        # Decrypt the AES key and IV using RSA
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        iv = private_key.decrypt(
            encrypted_iv,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Decrypt the file using AES-GCM with the key, IV, and auth_tag
        decrypted_file = decrypt_aes_gcm(enc_file, aes_key, iv, auth_tag)

        # Save decrypted file to a temp location
        os.makedirs(TEMP_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
            tmp_file.write(decrypted_file)
            tmp_file_path = tmp_file.name

        file_ext = tmp_file_path.rsplit('.', 1)[1].lower()
        extracted_text = extract_text_from_file(tmp_file_path, file_ext)

        os.remove(tmp_file_path)

        if not extracted_text:
            return jsonify({"error": "No text could be extracted from the file"}), 400

        if len(extracted_text) > MAX_TEXT_LENGTH:
            extracted_text = extracted_text[:MAX_TEXT_LENGTH]

        chunks = chunk_text_by_sentences(extracted_text, MAX_INPUT_TOKENS)
        partial_summaries = []

        for chunk in chunks:
            summary = summarizer(
                chunk,
                max_length=MAX_SUMMARY_LENGTH,
                min_length=MIN_SUMMARY_LENGTH,
                do_sample=False
            )[0]['summary_text']
            partial_summaries.append(summary)

        final_summary = " ".join(partial_summaries)

        if len(partial_summaries) > 1:
            final_summary = summarizer(
                final_summary,
                max_length=MAX_SUMMARY_LENGTH,
                min_length=MIN_SUMMARY_LENGTH,
                do_sample=False
            )[0]['summary_text']

        return jsonify({
            "summary": final_summary,
            "original_length": len(extracted_text),
            "summary_length": len(final_summary)
        })

    except Exception as e:
        app.logger.error(f"An error occurred: {e}")
        return jsonify({"error": "An error occurred during summarization."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8000)
