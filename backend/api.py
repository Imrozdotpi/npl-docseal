import os
import uuid
import shutil
import tempfile
import base64
import zipfile
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Import core modules exactly
from core.hasher import hash_file
from core.signer import sign_file, verify_signature
from core.encryptor import encrypt_file, decrypt_file
from core.timestamper import stamp_file, verify_timestamp

app = FastAPI(
    title="NPL DocSeal Dashboard API",
    description="Government-grade cybersecurity dashboard API",
    version="1.0.0"
)

# Enable CORS for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PRIVATE_KEY = Path("keys/private_key.pem")
PUBLIC_KEY = Path("keys/public_key.pem")

@app.post("/api/seal")
async def seal_file(
    document: UploadFile = File(...),
    password: str = Form(...),
    keypass: str = Form(...)
):
    """
    Seal document by hashing, signing, timestamping, and encrypting it.
    Returns the SHA-256 hash and a ZIP file containing the outputs (.enc, .sig, .ots).
    """
    if not PRIVATE_KEY.exists():
        raise HTTPException(status_code=500, detail="Private key keys/private_key.pem not found on server.")

    # Create a temporary directory inside the workspace
    temp_dir = Path(tempfile.mkdtemp(dir="."))
    try:
        original_filename = Path(document.filename).name
        temp_filepath = temp_dir / original_filename

        # Write uploaded file to temp_filepath
        with open(temp_filepath, "wb") as buffer:
            shutil.copyfileobj(document.file, buffer)

        # Compute SHA-256 hash
        sha256_hash = hash_file(str(temp_filepath))

        # Sign document using core signer
        try:
            sig_path = sign_file(str(temp_filepath), str(PRIVATE_KEY), keypass)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Key Passphrase authentication failed: {str(e)}")

        # Create OpenTimestamp proof
        try:
            ots_path = stamp_file(str(temp_filepath))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OpenTimestamps creation failed: {str(e)}")

        # Encrypt document using core encryptor
        try:
            enc_path = encrypt_file(str(temp_filepath), password)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

        # Package outputs into a single ZIP archive
        zip_filename = f"{temp_filepath.stem}_sealed.zip"
        zip_path = temp_dir / zip_filename
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(enc_path, arcname=Path(enc_path).name)
            zipf.write(sig_path, arcname=Path(sig_path).name)
            zipf.write(ots_path, arcname=Path(ots_path).name)

        # Base64-encode ZIP content for transmission
        with open(zip_path, "rb") as f:
            zip_data_base64 = base64.b64encode(f.read()).decode("utf-8")

        return {
            "hash": sha256_hash,
            "zip_filename": zip_filename,
            "zip_data": zip_data_base64
        }

    finally:
        # Securely clean up the temp directory
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass


@app.post("/api/verify")
async def verify_file(
    document_enc: UploadFile = File(...),
    document_sig: UploadFile = File(...),
    document_ots: UploadFile = File(...),
    password: str = Form(...)
):
    """
    Verify & Recover document.
    Decrypts the .enc file, checks the RSA-PSS signature, checks the OpenTimestamp proof,
    and returns a detailed audit report alongside the recovered document bytes.
    """
    if not PUBLIC_KEY.exists():
        raise HTTPException(status_code=500, detail="Public key keys/public_key.pem not found on server.")

    uuid_str = str(uuid.uuid4())
    
    # Define names in CWD to match decrypt_file behavior (which saves to path.stem in CWD)
    temp_enc_name = f"temp_{uuid_str}.enc"
    temp_sig_name = f"temp_{uuid_str}.sig"
    temp_ots_name = f"temp_{uuid_str}.ots"
    temp_dec_name = f"temp_{uuid_str}"  # Path(temp_enc_name).stem
    
    report = {
        "sha256": "unknown",
        "encryption_status": "failed",
        "signature_status": "unverified",
        "timestamp_status": "unverified",
        "authenticity_status": "compromised",
        "details": ""
    }

    try:
        # Save uploaded files locally
        with open(temp_enc_name, "wb") as buffer:
            shutil.copyfileobj(document_enc.file, buffer)
        with open(temp_sig_name, "wb") as buffer:
            shutil.copyfileobj(document_sig.file, buffer)
        with open(temp_ots_name, "wb") as buffer:
            shutil.copyfileobj(document_ots.file, buffer)

        # 1. Decrypt document
        try:
            decrypted_filename = decrypt_file(temp_enc_name, password)
            # Ensure it actually decrypted to temp_dec_name
            decrypted_filepath = Path(decrypted_filename)
            if not decrypted_filepath.exists():
                raise FileNotFoundError("Decrypted output file not found in workspace.")
            
            report["encryption_status"] = "decrypted"
            report["sha256"] = hash_file(str(decrypted_filepath))
            report["details"] += "AES-256-GCM Decryption Complete. "
        except Exception as e:
            report["encryption_status"] = "failed"
            report["details"] += f"Decryption failed: Authentication error or invalid password. "
            return {
                "decrypted_data": None,
                "original_filename": None,
                "report": report
            }

        # 2. Verify Digital Signature
        try:
            sig_valid = verify_signature(
                str(decrypted_filepath),
                temp_sig_name,
                str(PUBLIC_KEY)
            )
            if sig_valid:
                report["signature_status"] = "valid"
                report["details"] += "RSA-PSS Signature Valid. "
            else:
                report["signature_status"] = "invalid"
                report["details"] += "Signature Invalid (Document tampered or signed with different key). "
        except Exception as e:
            report["signature_status"] = "invalid"
            report["details"] += f"Signature check error: {str(e)}. "

        # 3. Verify OpenTimestamp
        try:
            ots_result = verify_timestamp(temp_ots_name)
            status = ots_result.get("status", "failed")
            report["timestamp_status"] = status
            
            if status == "confirmed":
                report["details"] += "OpenTimestamp Verified (Confirmed on Bitcoin blockchain). "
            elif status == "pending":
                report["details"] += "OpenTimestamp Pending (Awaiting block confirmation). "
            else:
                report["timestamp_status"] = "failed"
                report["details"] += "Timestamp Verification Failed. "
        except Exception as e:
            report["timestamp_status"] = "failed"
            report["details"] += f"Timestamp check error: {str(e)}. "

        # 4. Overall Authenticity Status
        if (
            report["encryption_status"] == "decrypted"
            and report["signature_status"] == "valid"
            and report["timestamp_status"] in ("confirmed", "pending")
        ):
            report["authenticity_status"] = "authentic"
        else:
            report["authenticity_status"] = "compromised"

        # Read decrypted original data
        with open(decrypted_filepath, "rb") as f:
            decrypted_data_base64 = base64.b64encode(f.read()).decode("utf-8")

        # Determine original filename based on the encrypted file name
        original_filename = Path(document_enc.filename).name
        if original_filename.endswith(".enc"):
            original_filename = original_filename[:-4]
        else:
            original_filename = "recovered_document.pdf"

        return {
            "decrypted_data": decrypted_data_base64,
            "original_filename": original_filename,
            "report": report
        }

    finally:
        # Securely delete all temporary workspace files
        for filename in [temp_enc_name, temp_sig_name, temp_ots_name, temp_dec_name]:
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except Exception:
                pass


# Serve the static frontend folder
frontend_dir = Path("frontend")
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
else:
    # During initial creation, directory might not exist yet, we will mount it later or handle it gracefully
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.api:app", host="127.0.0.1", port=8000, reload=True)
