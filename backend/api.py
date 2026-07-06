import os
import uuid
import shutil
import tempfile
import base64
import zipfile
import json
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Import core modules exactly
from core.hasher import hash_file
from core.signer import sign_file, verify_signature, sign_bytes, verify_bytes
from core.encryptor import encrypt_file, decrypt_file
from core.timestamper import stamp_file, verify_timestamp, upgrade_timestamp
from core.xml_parser import parse_xml
from core.merkle import build_merkle_tree, compare_trees

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
    Seal XML document by parsing it, building a Merkle tree, signing the Merkle root,
    timestamping it, encrypting the XML, and packaging the outputs.
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

        # Call parse_xml(temp_path) -> get parsed dict
        try:
            parsed = parse_xml(str(temp_filepath))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"XML parsing failed: {str(e)}")

        # Call build_merkle_tree(parsed) -> get merkle result
        try:
            merkle_result = build_merkle_tree(parsed)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Merkle tree building failed: {str(e)}")

        merkle_root = merkle_result["root"]

        # Sign the root: signature = sign_bytes(merkle_root.encode("utf-8"), private_key_path, keypass)
        # Note: Prehashed(SHA256) expects 32-byte hash, so try bytes.fromhex first.
        try:
            try:
                signature = sign_bytes(bytes.fromhex(merkle_root), str(PRIVATE_KEY), keypass)
            except ValueError:
                signature = sign_bytes(merkle_root.encode("utf-8"), str(PRIVATE_KEY), keypass)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Key Passphrase authentication failed: {str(e)}")

        # Save signature to <filename>.sig
        sig_path = temp_dir / f"{original_filename}.sig"
        with open(sig_path, "wb") as f:
            f.write(signature)

        # Call existing timestamper with the merkle root string
        temp_root_file = temp_dir / "merkle_root.txt"
        with open(temp_root_file, "w") as f:
            f.write(merkle_root)
        
        try:
            ots_temp_path = stamp_file(str(temp_root_file))
            ots_path = temp_dir / f"{original_filename}.ots"
            shutil.copy(ots_temp_path, ots_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OpenTimestamps creation failed: {str(e)}")

        # Call encrypt_file(temp_xml_path, password) -> get .enc path
        try:
            enc_path = encrypt_file(str(temp_filepath), password)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

        # Save merkle_proof.json -> <filename>_merkle_proof.json
        proof_path = temp_dir / f"{original_filename}_merkle_proof.json"
        proof_data = {
            "fields": merkle_result["fields"],
            "field_hashes": merkle_result["field_hashes"],
            "leaves": merkle_result["leaves"],
            "root": merkle_result["root"]
        }
        with open(proof_path, "w") as f:
            json.dump(proof_data, f, indent=2)

        # Package outputs into a single ZIP archive
        zip_filename = f"{Path(original_filename).stem}_sealed.zip"
        zip_path = temp_dir / zip_filename
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(enc_path, arcname=Path(enc_path).name)
            zipf.write(str(sig_path), arcname=f"{original_filename}.sig")
            zipf.write(str(ots_path), arcname=f"{original_filename}.ots")
            zipf.write(str(proof_path), arcname="merkle_proof.json")
            # Include public key
            zipf.write(str(PUBLIC_KEY), arcname="public_key.pem")

        # Base64-encode ZIP content for transmission
        with open(zip_path, "rb") as f:
            zip_data_base64 = base64.b64encode(f.read()).decode("utf-8")

        return {
            "hash": merkle_root,
            "field_count": len(merkle_result["fields"]),
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
    Verify & Recover document from a single ZIP package using Merkle tree validation.
    Extracts the contents, validates package contents strictly, decrypts, and runs
    cryptographic checks.
    """
    uuid_str = str(uuid.uuid4())
    temp_dir = Path(tempfile.mkdtemp(dir="."))
    temp_zip_path = temp_dir / f"uploaded_{uuid_str}.zip"
    
    # Define names in CWD to match decrypt_file behavior (which saves to path.stem in CWD)
    temp_enc_name = f"temp_{uuid_str}.enc"
    temp_sig_name = f"temp_{uuid_str}.sig"
    temp_ots_name = f"temp_{uuid_str}.ots"
    temp_pub_name = f"temp_{uuid_str}_pub.pem"
    temp_proof_name = f"temp_{uuid_str}_proof.json"
    temp_dec_name = f"temp_{uuid_str}"  # Path(temp_enc_name).stem
    original_filename = "recovered_document.xml"
    
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
                proof_files = [n for n in namelist if Path(n).name == 'merkle_proof.json']
                
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

                # Check for merkle_proof.json
                if len(proof_files) == 0:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: missing merkle_proof.json")
                if len(proof_files) > 1:
                    raise HTTPException(status_code=400, detail="Invalid NPL DocSeal package: multiple merkle_proof.json files found")

                # Extract ZIP contents to temporary directory
                zipf.extractall(temp_dir)
                
                # Copy targeted files to CWD with UUID prefixes for verification run
                shutil.copy(str(temp_dir / enc_files[0]), temp_enc_name)
                shutil.copy(str(temp_dir / sig_files[0]), temp_sig_name)
                shutil.copy(str(temp_dir / ots_files[0]), temp_ots_name)
                shutil.copy(str(temp_dir / pub_files[0]), temp_pub_name)
                shutil.copy(str(temp_dir / proof_files[0]), temp_proof_name)
                
                # Determine original filename based on the encrypted file name
                extracted_enc_name = Path(enc_files[0]).name
                if extracted_enc_name.endswith(".enc"):
                    original_filename = extracted_enc_name[:-4]
                else:
                    original_filename = "recovered_document.xml"
                
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
        except Exception as e:
            return JSONResponse(status_code=200, content={
                "overall": "FAIL",
                "signature_valid": False,
                "root_matches": False,
                "timestamp": {"status": "failed", "detail": f"Decryption failed: {str(e)}"},
                "fields": {}
            })

        # 2. Parse decrypted XML
        try:
            current_parsed = parse_xml(str(decrypted_filepath))
        except Exception as e:
            return JSONResponse(status_code=200, content={
                "overall": "FAIL",
                "signature_valid": False,
                "root_matches": False,
                "timestamp": {"status": "failed", "detail": f"XML parse error: {str(e)}"},
                "fields": {}
            })

        # 3. Load merkle_proof.json
        try:
            with open(temp_proof_name, "r") as f:
                stored_proof = json.load(f)
        except Exception as e:
            return JSONResponse(status_code=200, content={
                "overall": "FAIL",
                "signature_valid": False,
                "root_matches": False,
                "timestamp": {"status": "failed", "detail": f"Failed to load Merkle proof: {str(e)}"},
                "fields": {}
            })

        # 4. Compare trees
        try:
            compare_result = compare_trees(stored_proof, current_parsed)
            root_matches = compare_result.get("root_matches", False)
            fields_report = compare_result.get("fields", {})
        except Exception as e:
            return JSONResponse(status_code=200, content={
                "overall": "FAIL",
                "signature_valid": False,
                "root_matches": False,
                "timestamp": {"status": "failed", "detail": f"Tree comparison failed: {str(e)}"},
                "fields": {}
            })

        # 5. Verify RSA-PSS signature over the root
        signature_valid = False
        try:
            with open(temp_sig_name, "rb") as f:
                signature_bytes = f.read()
            stored_root = stored_proof.get("root", "")
            
            try:
                signature_valid = verify_bytes(bytes.fromhex(stored_root), signature_bytes, temp_pub_name)
            except ValueError:
                signature_valid = verify_bytes(stored_root.encode("utf-8"), signature_bytes, temp_pub_name)
        except Exception:
            signature_valid = False

        # 6. Verify OpenTimestamp
        timestamp_status = "failed"
        timestamp_detail = "Timestamp verification failed."
        try:
            # Try to upgrade timestamp first
            try:
                upgrade_timestamp(temp_ots_name)
            except Exception:
                pass

            ots_result = verify_timestamp(temp_ots_name)
            timestamp_status = ots_result.get("status", "failed")
            
            if timestamp_status == "confirmed":
                timestamp_detail = f"OpenTimestamp Verified (Confirmed on Bitcoin blockchain at block {ots_result.get('block_height')})."
            elif timestamp_status == "pending":
                timestamp_detail = "OpenTimestamp Pending (Awaiting block confirmation)."
            else:
                timestamp_detail = "Timestamp Verification Failed."
        except Exception as e:
            timestamp_status = "failed"
            timestamp_detail = f"Timestamp check error: {str(e)}"

        # Compute overall status
        overall = "PASS" if (signature_valid and root_matches) else "FAIL"

        # Read decrypted original data
        decrypted_data_base64 = None
        if decrypted_filepath.exists():
            with open(decrypted_filepath, "rb") as f:
                decrypted_data_base64 = base64.b64encode(f.read()).decode("utf-8")

        return {
            "overall": overall,
            "signature_valid": signature_valid,
            "root_matches": root_matches,
            "timestamp": {
                "status": timestamp_status,
                "block_height": ots_result.get("block_height") if 'ots_result' in locals() else None,
                "detail": timestamp_detail
            },
            "fields": fields_report,
            "decrypted_data": decrypted_data_base64,
            "original_filename": original_filename
        }

    finally:
        # Securely clean up the temp directory
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass
        # Securely delete all temporary workspace files in CWD
        for filename in [temp_enc_name, temp_sig_name, temp_ots_name, temp_pub_name, temp_proof_name, temp_dec_name]:
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
