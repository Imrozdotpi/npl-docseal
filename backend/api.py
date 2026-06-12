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
    Returns the SHA-256 hash and a ZIP file containing the outputs (.enc, .sig, .ots, and public_key.pem).
    """
    if not PRIVATE_KEY.exists():
        raise HTTPException(status_code=500, detail="Private key keys/private_key.pem not found on server.")
    if not PUBLIC_KEY.exists():
        raise HTTPException(status_code=500, detail="Public key keys/public_key.pem not found on server.")

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
            # Include public key
            zipf.write(str(PUBLIC_KEY), arcname="public_key.pem")

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
    document_zip: UploadFile = File(...),
    password: str = Form(...)
):
    """
    Verify & Recover document from a single ZIP package.
    Extracts the contents, validates package contents strictly, decrypts, and runs
    cryptographic checks using the sender's public key from the archive.
    """
    uuid_str = str(uuid.uuid4())
    temp_dir = Path(tempfile.mkdtemp(dir="."))
    temp_zip_path = temp_dir / f"uploaded_{uuid_str}.zip"
    
    # Define names in CWD to match decrypt_file behavior (which saves to path.stem in CWD)
    temp_enc_name = f"temp_{uuid_str}.enc"
    temp_sig_name = f"temp_{uuid_str}.sig"
    temp_ots_name = f"temp_{uuid_str}.ots"
    temp_pub_name = f"temp_{uuid_str}_pub.pem"
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
        # Save uploaded zip file locally
        with open(temp_zip_path, "wb") as buffer:
            shutil.copyfileobj(document_zip.file, buffer)

        # Strict validation of ZIP contents
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                namelist = zipf.namelist()
                
                enc_files = [n for n in namelist if n.endswith('.enc')]
                sig_files = [n for n in namelist if n.endswith('.sig')]
                ots_files = [n for n in namelist if n.endswith('.ots')]
                pub_files = [n for n in namelist if Path(n).name == 'public_key.pem']
                
                # Check for public key pem file
                if len(pub_files) == 0:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: missing public_key.pem")
                if len(pub_files) > 1:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: multiple public_key.pem files found")
                
                # Check for enc file
                if len(enc_files) == 0:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: missing .enc file")
                if len(enc_files) > 1:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: multiple .enc files found")
                
                # Check for sig file
                if len(sig_files) == 0:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: missing .sig file")
                if len(sig_files) > 1:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: multiple .sig files found")
                
                # Check for ots file
                if len(ots_files) == 0:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: missing .ots file")
                if len(ots_files) > 1:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: multiple .ots files found")

                # Extract ZIP contents to temporary directory
                zipf.extractall(temp_dir)
                
                # Copy targeted files to CWD with UUID prefixes for verification run
                shutil.copy(str(temp_dir / enc_files[0]), temp_enc_name)
                shutil.copy(str(temp_dir / sig_files[0]), temp_sig_name)
                shutil.copy(str(temp_dir / ots_files[0]), temp_ots_name)
                shutil.copy(str(temp_dir / pub_files[0]), temp_pub_name)
                
                # Determine original filename based on the encrypted file name
                extracted_enc_name = Path(enc_files[0]).name
                if extracted_enc_name.endswith(".enc"):
                    original_filename = extracted_enc_name[:-4]
                else:
                    original_filename = "recovered_document.pdf"

        except HTTPException as he:
            raise he
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read or extract ZIP archive: {str(e)}")

        # 1. Decrypt document
        try:
            decrypted_filename = decrypt_file(temp_enc_name, password)
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

        # 2. Verify Digital Signature using the extracted public key
        try:
            sig_valid = verify_signature(
                str(decrypted_filepath),
                temp_sig_name,
                temp_pub_name
            )
            if sig_valid:
                report["signature_status"] = "valid"
                report["details"] += "RSA-PSS Signature Valid (Using sender public key). "
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

        return {
            "decrypted_data": decrypted_data_base64,
            "original_filename": original_filename,
            "report": report
        }

    finally:
        # Securely clean up the temp directory
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass
        # Securely delete all temporary workspace files in CWD
        for filename in [temp_enc_name, temp_sig_name, temp_ots_name, temp_pub_name, temp_dec_name]:
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except Exception:
                pass


# Serve the static frontend folder
frontend_dir = Path("frontend")
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.api:app", host="127.0.0.1", port=8000, reload=True)
