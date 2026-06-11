import os
import base64
import shutil
import zipfile
from pathlib import Path
import requests

API_URL = "http://127.0.0.1:8000"

def run_tests():
    print("==================================================")
    print("STARTING NPL DOCSEAL API INTEGRATION TESTS")
    print("==================================================")
    
    # 1. Create a dummy document for testing
    test_doc_path = Path("tests/integration_test_doc.pdf")
    test_content = b"CONFIDENTIAL NATIONAL PHYSICAL LABORATORY SECURITY DOCUMENT - LEVEL 5"
    with open(test_doc_path, "wb") as f:
        f.write(test_content)
    
    print(f"[TEST] Created dummy test document: {test_doc_path}")

    # Temporary directory to hold extracted files
    extract_dir = Path("tests/extracted_temp")
    extract_dir.mkdir(exist_ok=True)
    
    try:
        # 2. Test Sealing
        print("\n[TEST 1] Sealing Document via /api/seal...")
        with open(test_doc_path, "rb") as doc_file:
            files = {"document": ("integration_test_doc.pdf", doc_file, "application/pdf")}
            data = {"password": "karan", "keypass": "karan"}
            
            response = requests.post(f"{API_URL}/api/seal", files=files, data=data)
            
        assert response.status_code == 200, f"Seal failed with status {response.status_code}: {response.text}"
        res_json = response.json()
        
        sealed_hash = res_json["hash"]
        zip_filename = res_json["zip_filename"]
        zip_data_b64 = res_json["zip_data"]
        
        print(f"  - Generated SHA-256 Hash: {sealed_hash}")
        print(f"  - Received ZIP Archive: {zip_filename}")
        
        # Save ZIP file
        zip_path = Path("tests/sealed_payload.zip")
        with open(zip_path, "wb") as f:
            f.write(base64.b64decode(zip_data_b64))
            
        # Extract files from ZIP
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(extract_dir)
            
        enc_file = extract_dir / "integration_test_doc.pdf.enc"
        sig_file = extract_dir / "integration_test_doc.pdf.sig"
        ots_file = extract_dir / "integration_test_doc.pdf.ots"
        
        assert enc_file.exists(), "Encrypted file missing in ZIP"
        assert sig_file.exists(), "Signature file missing in ZIP"
        assert ots_file.exists(), "Timestamp file missing in ZIP"
        print("  - Successfully extracted .enc, .sig, and .ots from ZIP package.")
        
        # 3. Test Successful Verification & Recovery
        print("\n[TEST 2] Verifying & Recovering Document (Valid Run)...")
        with open(enc_file, "rb") as fe, open(sig_file, "rb") as fs, open(ots_file, "rb") as fo:
            files = {
                "document_enc": ("integration_test_doc.pdf.enc", fe, "application/octet-stream"),
                "document_sig": ("integration_test_doc.pdf.sig", fs, "application/octet-stream"),
                "document_ots": ("integration_test_doc.pdf.ots", fo, "application/octet-stream")
            }
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200, f"Verify failed: {response.text}"
        res_json = response.json()
        report = res_json["report"]
        
        print(f"  - Encryption Status: {report['encryption_status']}")
        print(f"  - Signature Status: {report['signature_status']}")
        print(f"  - Timestamp Status: {report['timestamp_status']}")
        print(f"  - Authenticity Status: {report['authenticity_status']}")
        print(f"  - Log Details: {report['details']}")
        
        assert report["encryption_status"] == "decrypted", "Decryption status should be decrypted"
        assert report["signature_status"] == "valid", "Signature should be valid"
        assert report["timestamp_status"] in ("confirmed", "pending"), "Timestamp status should be confirmed or pending"
        assert report["authenticity_status"] == "authentic", "Overall authenticity should be authentic"
        
        recovered_data = base64.b64decode(res_json["decrypted_data"])
        assert recovered_data == test_content, "Recovered document content mismatch!"
        print("  - Recovered document matched original content perfectly.")

        # 4. Test Tamper Detection: Incorrect Password
        print("\n[TEST 3] Tamper Detection: Incorrect Password...")
        with open(enc_file, "rb") as fe, open(sig_file, "rb") as fs, open(ots_file, "rb") as fo:
            files = {
                "document_enc": ("integration_test_doc.pdf.enc", fe, "application/octet-stream"),
                "document_sig": ("integration_test_doc.pdf.sig", fs, "application/octet-stream"),
                "document_ots": ("integration_test_doc.pdf.ots", fo, "application/octet-stream")
            }
            data = {"password": "wrong_password_abc"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200
        res_json = response.json()
        report = res_json["report"]
        
        print(f"  - Encryption Status: {report['encryption_status']}")
        print(f"  - Authenticity Status: {report['authenticity_status']}")
        print(f"  - Log Details: {report['details']}")
        
        assert report["encryption_status"] == "failed"
        assert report["authenticity_status"] == "compromised"
        assert res_json["decrypted_data"] is None
        print("  - Correctly identified decryption failure and flagged as compromised.")

        # 5. Test Tamper Detection: Modified Signature File
        print("\n[TEST 4] Tamper Detection: Modified Signature...")
        # Create a tampered signature file
        tampered_sig_file = extract_dir / "tampered.sig"
        with open(sig_file, "rb") as fs:
            sig_bytes = bytearray(fs.read())
        # Flip a byte in the signature
        if len(sig_bytes) > 10:
            sig_bytes[5] ^= 0xFF
        with open(tampered_sig_file, "wb") as fts:
            fts.write(sig_bytes)

        with open(enc_file, "rb") as fe, open(tampered_sig_file, "rb") as fs, open(ots_file, "rb") as fo:
            files = {
                "document_enc": ("integration_test_doc.pdf.enc", fe, "application/octet-stream"),
                "document_sig": ("integration_test_doc.pdf.sig", fs, "application/octet-stream"),
                "document_ots": ("integration_test_doc.pdf.ots", fo, "application/octet-stream")
            }
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200
        res_json = response.json()
        report = res_json["report"]
        
        print(f"  - Encryption Status: {report['encryption_status']}")
        print(f"  - Signature Status: {report['signature_status']}")
        print(f"  - Authenticity Status: {report['authenticity_status']}")
        print(f"  - Log Details: {report['details']}")
        
        assert report["encryption_status"] == "decrypted"
        assert report["signature_status"] == "invalid"
        assert report["authenticity_status"] == "compromised"
        print("  - Correctly detected signature tampering and flagged as compromised.")

        # 6. Test Tamper Detection: Modified OpenTimestamp Receipt
        print("\n[TEST 5] Tamper Detection: Tampered OpenTimestamp Receipt...")
        # Create a tampered OTS file
        tampered_ots_file = extract_dir / "tampered.ots"
        with open(ots_file, "rb") as fo:
            ots_bytes = bytearray(fo.read())
        # Append some garbage bytes
        ots_bytes.extend(b"TAMPERED_DETAILS")
        with open(tampered_ots_file, "wb") as fto:
            fto.write(ots_bytes)

        with open(enc_file, "rb") as fe, open(sig_file, "rb") as fs, open(tampered_ots_file, "rb") as fo:
            files = {
                "document_enc": ("integration_test_doc.pdf.enc", fe, "application/octet-stream"),
                "document_sig": ("integration_test_doc.pdf.sig", fs, "application/octet-stream"),
                "document_ots": ("integration_test_doc.pdf.ots", fo, "application/octet-stream")
            }
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200
        res_json = response.json()
        report = res_json["report"]
        
        print(f"  - Encryption Status: {report['encryption_status']}")
        print(f"  - Timestamp Status: {report['timestamp_status']}")
        print(f"  - Authenticity Status: {report['authenticity_status']}")
        print(f"  - Log Details: {report['details']}")
        
        assert report["encryption_status"] == "decrypted"
        assert report["timestamp_status"] == "failed"
        assert report["authenticity_status"] == "compromised"
        print("  - Correctly identified OpenTimestamp tampering and flagged as compromised.")

        print("\n==================================================")
        print("ALL API INTEGRATION TESTS PASSED SUCCESSFULLY!")
        print("==================================================")

    finally:
        # Clean up temporary test files
        print("\n[CLEANUP] Removing generated test payloads...")
        if test_doc_path.exists():
            os.remove(test_doc_path)
        if Path("tests/sealed_payload.zip").exists():
            os.remove("tests/sealed_payload.zip")
        if extract_dir.exists():
            shutil.rmtree(extract_dir)

if __name__ == "__main__":
    run_tests()
