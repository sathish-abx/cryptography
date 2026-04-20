import streamlit as st
import os
import json
import shutil
import traceback
from datetime import datetime

# PDF
from reportlab.pdfgen import canvas

# Crypto
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID
import cryptography.x509 as x509
from cryptography.hazmat.primitives.serialization import Encoding

# Signing
from pyhanko.sign import signers
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigFieldSpec
from pyhanko_certvalidator import ValidationContext

# QR
import qrcode

# =========================
# CONFIG
# =========================
KEY_FILE = "private_key.pem"
CERT_FILE = "certificate.pem"
GEN_DIR = "generated_files"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "error.log")

# =========================
# LOGGING
# =========================
def log_error(error, context=""):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)

        with open(LOG_FILE, "a") as f:
            f.write("\n" + "="*80 + "\n")
            f.write(f"TIME: {datetime.now()}\n")
            f.write(f"CONTEXT: {context}\n")
            f.write(f"ERROR: {str(error)}\n")
            f.write("TRACEBACK:\n")
            f.write(traceback.format_exc())
            f.write("\n")
    except:
        pass

# =========================
# FOLDER CLEANUP
# =========================
def reset_generated_folder():
    try:
        if os.path.exists(GEN_DIR):
            shutil.rmtree(GEN_DIR)
        os.makedirs(GEN_DIR, exist_ok=True)
    except Exception as e:
        log_error(e, "reset_generated_folder")
        raise Exception("Failed to reset generated files folder")

# =========================
# KEY GENERATION
# =========================
def generate_keys():
    try:
        if not os.path.exists(KEY_FILE):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            with open(KEY_FILE, "wb") as f:
                f.write(
                    key.private_bytes(
                        Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    )
                )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Local CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Local Signer"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 5))
                .sign(key, hashes.SHA256())
            )

            with open(CERT_FILE, "wb") as f:
                f.write(cert.public_bytes(Encoding.PEM))

    except Exception as e:
        log_error(e, "generate_keys")
        raise Exception(f"Key generation failed: {str(e)}")

# =========================
# CREATE PDF + QR
# =========================
def create_pdf(name, course, filename):
    try:
        c = canvas.Canvas(filename)
        now = datetime.now()

        c.drawString(100, 750, "Certificate of Completion")
        c.drawString(100, 700, f"Name: {name}")
        c.drawString(100, 670, f"Course: {course}")
        c.drawString(100, 640, f"Date: {now}")

        qr_payload = {
            "name": name,
            "course": course,
            "issued_at": str(now),
            "issuer": "My Local CA"
        }

        qr = qrcode.make(json.dumps(qr_payload))
        qr_path = os.path.join(GEN_DIR, "qr.png")
        qr.save(qr_path)

        c.drawImage(qr_path, 400, 600, width=120, height=120)

        c.drawString(100, 550, "Digitally Signed Document")
        c.drawString(100, 520, "Verify using QR or signature panel")

        c.save()

    except Exception as e:
        log_error(e, "create_pdf")
        raise Exception(f"PDF creation failed: {str(e)}")

# =========================
# SIGN PDF
# =========================
def sign_pdf(input_pdf, output_pdf):
    try:
        signer = signers.SimpleSigner.load(
            key_file=KEY_FILE,
            cert_file=CERT_FILE,
        )

        with open(input_pdf, "rb") as inf:
            writer = IncrementalPdfFileWriter(inf)

            with open(output_pdf, "wb") as outf:
                signers.sign_pdf(
                    writer,
                    signature_meta=signers.PdfSignatureMetadata(field_name="Sig1"),
                    signer=signer,
                    new_field_spec=SigFieldSpec(
                        sig_field_name="Sig1",
                        box=(100, 400, 400, 500)
                    ),
                    output=outf,
                )

    except Exception as e:
        log_error(e, "sign_pdf")
        raise Exception(f"Signing failed: {str(e)}")

# =========================
# TAMPER PDF
# =========================
def tamper_pdf(input_pdf, output_pdf):
    try:
        with open(input_pdf, "rb") as f:
            data = bytearray(f.read())

        target = b"Certificate"
        index = data.find(target)

        if index != -1:
            data[index] = ord('X')
        else:
            data[len(data)//2] = (data[len(data)//2] + 1) % 256

        with open(output_pdf, "wb") as f:
            f.write(data)

    except Exception as e:
        log_error(e, "tamper_pdf")
        raise Exception(f"Tampering failed: {str(e)}")

# =========================
# VERIFY (FULL DETAILS - from v1)
# =========================
def verify_pdf(file_path):
    try:
        with open(file_path, "rb") as f:
            reader = PdfFileReader(f)
            sigs = list(reader.embedded_signatures)

            if not sigs:
                return {"status": "NO SIGNATURE ❌"}

            sig = sigs[0]
            vc = ValidationContext(allow_fetching=False)
            status = validate_pdf_signature(sig, vc)

            cert = sig.signer_cert

            if not status.intact:
                final_status = "TAMPERED ❌"
            elif status.intact and status.valid:
                final_status = "VALID ✅"
            else:
                final_status = "UNKNOWN ⚠"

            return {
                "status": final_status,
                "document_intact": status.intact,
                "signature_valid": status.valid,
                "signer_name": cert.subject.native.get("common_name"),
                "issuer": cert.issuer.human_friendly,
                "valid_from": str(cert.not_valid_before),
                "valid_to": str(cert.not_valid_after),
                "algorithm": cert.signature_algo,
            }

    except Exception as e:
        log_error(e, "verify_pdf")
        return {"status": f"ERROR ❌ {str(e)}"}

# =========================
# STREAMLIT UI
# =========================
st.title("🔐 PDF Signing + Verification + Tamper System")

tab1, tab2 = st.tabs(["Create & Sign", "Verify"])

generate_keys()

# =========================
# CREATE + SIGN
# =========================
with tab1:
    name = st.text_input("Name")
    course = st.text_input("Course")

    if st.button("Generate Signed PDF"):
        try:
            if not name or not course:
                raise Exception("All fields required")

            reset_generated_folder()

            temp = os.path.join(GEN_DIR, "temp.pdf")
            signed = os.path.join(GEN_DIR, "signed.pdf")

            create_pdf(name, course, temp)
            sign_pdf(temp, signed)

            with open(signed, "rb") as f:
                st.success("Signed Successfully ✅")
                st.download_button("Download Signed PDF", f, "signed.pdf")

        except Exception as e:
            log_error(e, "Generate Signed PDF")
            st.error(str(e))

    if st.button("Tamper Signed PDF"):
        try:
            signed = os.path.join(GEN_DIR, "signed.pdf")
            tampered = os.path.join(GEN_DIR, "tampered.pdf")

            if not os.path.exists(signed):
                raise Exception("Generate signed PDF first")

            tamper_pdf(signed, tampered)

            with open(tampered, "rb") as f:
                st.warning("Tampered PDF generated ❌")
                st.download_button("Download Tampered PDF", f, "tampered.pdf")

        except Exception as e:
            log_error(e, "Tamper Signed PDF")
            st.error(str(e))

# =========================
# VERIFY
# =========================
with tab2:
    uploaded = st.file_uploader("Upload PDF", type=["pdf"])

    if uploaded:
        try:
            upload_path = os.path.join(GEN_DIR, "uploaded.pdf")
            with open(upload_path, "wb") as f:
                f.write(uploaded.read())

            result = verify_pdf(upload_path)

            st.write("### 🔍 Verification Result")
            for k, v in result.items():
                st.write(f"**{k}** : {v}")

        except Exception as e:
            log_error(e, "Verify PDF")
            st.error(str(e))