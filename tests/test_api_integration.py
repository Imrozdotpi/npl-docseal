import os
import base64
import shutil
import zipfile
from pathlib import Path
import requests

API_URL = "http://127.0.0.1:8000"

def create_modified_zip(src_zip, dest_zip, remove_files=None, add_files=None, modify_files=None):
    """
    Helper to extract a ZIP, modify its contents (remove, add, or tamper files), and rebuild it.
    """
    temp_extract = Path("tests/zip_temp")
    temp_extract.mkdir(exist_ok=True)
    
    try:
        # Extract original ZIP
        with zipfile.ZipFile(src_zip, 'r') as zipf:
            zipf.extractall(temp_extract)
            
        # Perform removals
        if remove_files:
            for f in remove_files:
                p = temp_extract / f
                if p.exists():
                    os.remove(p)
                    
        # Perform additions
        if add_files:
            for name, content in add_files.items():
                with open(temp_extract / name, "wb") as f:
                    f.write(content)
                    
        # Perform modifications (tampering)
        if modify_files:
            for name, modifier in modify_files.items():
                p = temp_extract / name
                if p.exists():
                    with open(p, "rb") as f:
                        data = f.read()
                    with open(p, "wb") as f:
                        f.write(modifier(data))
                        
        # Rebuild ZIP
        with zipfile.ZipFile(dest_zip, 'w') as zipf:
            for root, dirs, files in os.walk(temp_extract):
                for file in files:
                    zipf.write(Path(root) / file, arcname=file)
    finally:
        if temp_extract.exists():
            shutil.rmtree(temp_extract)


def run_tests():
    print("==================================================")
    print("STARTING NPL DOCSEAL XML/MERKLE API INTEGRATION TESTS")
    print("==================================================")
    
    # Create temp directories
    tests_dir = Path("tests")
    tests_dir.mkdir(exist_ok=True)
    
    # 1. Create a dummy XML document for testing
    test_doc_path = tests_dir / "integration_test_doc.xml"
    test_content = """<?xml version="1.0" encoding="UTF-8"?>
<CalibrationCertificate>
    <Organization>CSIR-NPL</Organization>
    <CertificateNumber>CSIR-NPL-2026-999</CertificateNumber>
    <CalibrationDate>2026-07-06</CalibrationDate>
    <DateOfIssue>2026-07-06</DateOfIssue>
    <Methodology>Direct Comparison</Methodology>
    <Traceability>CSIR-NPL Standards</Traceability>
    <Instrument>
        <Model>Digital Multimeter</Model>
        <ModelNumber>DMM-8848</ModelNumber>
        <SerialNumber>SN-DMM-12345</SerialNumber>
        <Make>NPL Instruments</Make>
    </Instrument>
    <EnvironmentalConditions>
        <Temperature>23.4 C</Temperature>
        <RelativeHumidity>48.2%</RelativeHumidity>
    </EnvironmentalConditions>
    <Results>
        <Measurement>
            <IndicatedValueA>10.000 V</IndicatedValueA>
            <MeasuredValueA>10.002 V</MeasuredValueA>
            <ExpandedUncertaintyPercent>0.05%</ExpandedUncertaintyPercent>
        </Measurement>
    </Results>
</CalibrationCertificate>
"""
    with open(test_doc_path, "w") as f:
        f.write(test_content)
    
    print(f"[TEST] Created dummy XML test document: {test_doc_path}")

    # File paths for testing payloads
    sealed_zip = tests_dir / "sealed_payload.zip"
    tampered_sig_zip = tests_dir / "tampered_sig.zip"
    tampered_ots_zip = tests_dir / "tampered_ots.zip"
    missing_pub_zip = tests_dir / "missing_pub.zip"
    missing_sig_zip = tests_dir / "missing_sig.zip"
    duplicate_enc_zip = tests_dir / "duplicate_enc.zip"
    duplicate_ots_zip = tests_dir / "duplicate_ots.zip"
    
    try:
        # 2. Test Sealing (Creates sealed ZIP)
        print("\n[TEST 1] Sealing XML Document via /api/seal...")
        with open(test_doc_path, "rb") as doc_file:
            files = {"document": ("integration_test_doc.xml", doc_file, "text/xml")}
            data = {"password": "karan", "keypass": "karan"}
            
            response = requests.post(f"{API_URL}/api/seal", files=files, data=data)
            
        assert response.status_code == 200, f"Seal failed with status {response.status_code}: {response.text}"
        res_json = response.json()
        
        sealed_hash = res_json["hash"]
        zip_filename = res_json["zip_filename"]
        zip_data_b64 = res_json["zip_data"]
        
        print(f"  - Generated Merkle Root: {sealed_hash}")
        print(f"  - Received ZIP Archive: {zip_filename}")
        
        # Save ZIP file
        with open(sealed_zip, "wb") as f:
            f.write(base64.b64decode(zip_data_b64))
        print(f"  - Saved sealed ZIP package to: {sealed_zip}")

        # 3. Test Successful Verification using single ZIP
        print("\n[TEST 2] Verifying & Recovering Document (Valid Single ZIP Run)...")
        with open(sealed_zip, "rb") as fz:
            files = {"document_zip": ("sealed_payload.zip", fz, "application/zip")}
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200, f"Verify failed with status {response.status_code}: {response.text}"
        res_json = response.json()
        
        print(f"  - Overall Status: {res_json['overall']}")
        print(f"  - Signature Valid: {res_json['signature_valid']}")
        print(f"  - Root Matches: {res_json['root_matches']}")
        print(f"  - Timestamp Status: {res_json['timestamp']['status']}")
        
        assert res_json["overall"] == "PASS", "Overall verification should be PASS"
        assert res_json["signature_valid"] is True, "Signature should be valid"
        assert res_json["root_matches"] is True, "Merkle root should match"
        assert res_json["timestamp"]["status"] in ("confirmed", "pending"), "Timestamp status should be confirmed or pending"
        assert res_json["fields"]["organization"]["status"] == "INTACT", "Organization status should be INTACT"
        assert res_json["fields"]["organization"]["value"] == "CSIR-NPL", "Organization value should be CSIR-NPL"
        print("  - Verified XML document integrity and Merkle fields perfectly.")

        # 4. Test Tamper Detection: Incorrect Password
        print("\n[TEST 3] Tamper Detection: Incorrect Password...")
        with open(sealed_zip, "rb") as fz:
            files = {"document_zip": ("sealed_payload.zip", fz, "application/zip")}
            data = {"password": "wrong_password_abc"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200
        res_json = response.json()
        
        print(f"  - Overall Status: {res_json['overall']}")
        print(f"  - Signature Valid: {res_json['signature_valid']}")
        print(f"  - Root Matches: {res_json['root_matches']}")
        
        assert res_json["overall"] == "FAIL", "Overall status should be FAIL on bad password"
        assert res_json["signature_valid"] is False
        assert res_json["root_matches"] is False
        print("  - Correctly identified decryption failure and flagged overall as FAIL.")

        # 5. Test Tamper Detection: Modified Signature inside ZIP
        print("\n[TEST 4] Tamper Detection: Modified Signature...")
        
        # Modify signature file bytes inside ZIP (flip a byte)
        def modify_sig(data):
            b = bytearray(data)
            if len(b) > 10:
                b[5] ^= 0xFF
            return bytes(b)
            
        create_modified_zip(
            sealed_zip, 
            tampered_sig_zip, 
            modify_files={"integration_test_doc.xml.sig": modify_sig}
        )
        
        with open(tampered_sig_zip, "rb") as fz:
            files = {"document_zip": ("tampered_sig.zip", fz, "application/zip")}
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200
        res_json = response.json()
        
        print(f"  - Overall Status: {res_json['overall']}")
        print(f"  - Signature Valid: {res_json['signature_valid']}")
        print(f"  - Root Matches: {res_json['root_matches']}")
        
        assert res_json["overall"] == "FAIL", "Overall status should be FAIL on tampered signature"
        assert res_json["signature_valid"] is False
        assert res_json["root_matches"] is True
        print("  - Correctly detected signature tampering inside the ZIP package.")

        # 6. Test Tamper Detection: Modified OpenTimestamp Receipt inside ZIP
        print("\n[TEST 5] Tamper Detection: Tampered OpenTimestamp Receipt...")
        
        # Modify OTS file bytes inside ZIP (append bytes)
        create_modified_zip(
            sealed_zip,
            tampered_ots_zip,
            modify_files={"integration_test_doc.xml.ots": lambda d: d + b"TAMPERED_DETAILS"}
        )
        
        with open(tampered_ots_zip, "rb") as fz:
            files = {"document_zip": ("tampered_ots.zip", fz, "application/zip")}
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        assert response.status_code == 200
        res_json = response.json()
        
        print(f"  - Overall Status: {res_json['overall']}")
        print(f"  - Timestamp Status: {res_json['timestamp']['status']}")
        
        # Overall status is still PASS because signature and root are intact, but timestamp failed
        assert res_json["overall"] == "PASS"
        assert res_json["timestamp"]["status"] == "failed"
        print("  - Correctly identified OpenTimestamp tampering inside the ZIP package.")

        # =====================================================================
        # NEGATIVE TESTS FOR MALFORMED ZIP FILES
        # =====================================================================
        print("\n[TEST 6] Negative Test: Missing public_key.pem...")
        create_modified_zip(sealed_zip, missing_pub_zip, remove_files=["public_key.pem"])
        
        with open(missing_pub_zip, "rb") as fz:
            files = {"document_zip": ("missing_pub.zip", fz, "application/zip")}
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        print(f"  - API Response Code: {response.status_code}")
        print(f"  - Error Detail: {response.text}")
        assert response.status_code == 400
        assert "missing public_key.pem" in response.json()["detail"].lower()
        print("  - Correctly rejected ZIP missing public_key.pem with HTTP 400.")

        print("\n[TEST 7] Negative Test: Missing digital signature (.sig)...")
        create_modified_zip(sealed_zip, missing_sig_zip, remove_files=["integration_test_doc.xml.sig"])
        
        with open(missing_sig_zip, "rb") as fz:
            files = {"document_zip": ("missing_sig.zip", fz, "application/zip")}
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        print(f"  - API Response Code: {response.status_code}")
        print(f"  - Error Detail: {response.text}")
        assert response.status_code == 400
        assert "missing .sig file" in response.json()["detail"].lower()
        print("  - Correctly rejected ZIP missing digital signature with HTTP 400.")

        print("\n[TEST 8] Negative Test: Multiple/Duplicate encrypted (.enc) files...")
        create_modified_zip(
            sealed_zip, 
            duplicate_enc_zip, 
            add_files={"extra_document.xml.enc": b"DUPLICATE_ENCRYPTED_DATA"}
        )
        
        with open(duplicate_enc_zip, "rb") as fz:
            files = {"document_zip": ("duplicate_enc.zip", fz, "application/zip")}
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        print(f"  - API Response Code: {response.status_code}")
        print(f"  - Error Detail: {response.text}")
        assert response.status_code == 400
        assert "multiple .enc files found" in response.json()["detail"].lower()
        print("  - Correctly rejected ZIP with duplicate encrypted payloads with HTTP 400.")

        print("\n[TEST 9] Negative Test: Multiple/Duplicate timestamp (.ots) files...")
        create_modified_zip(
            sealed_zip,
            duplicate_ots_zip,
            add_files={"extra_proof.xml.ots": b"DUPLICATE_TIMESTAMP_PROOF"}
        )
        
        with open(duplicate_ots_zip, "rb") as fz:
            files = {"document_zip": ("duplicate_ots.zip", fz, "application/zip")}
            data = {"password": "karan"}
            response = requests.post(f"{API_URL}/api/verify", files=files, data=data)
            
        print(f"  - API Response Code: {response.status_code}")
        print(f"  - Error Detail: {response.text}")
        assert response.status_code == 400
        assert "multiple .ots files found" in response.json()["detail"].lower()
        print("  - Correctly rejected ZIP with duplicate timestamp proofs with HTTP 400.")

        print("\n==================================================")
        print("ALL API INTEGRATION TESTS PASSED SUCCESSFULLY!")
        print("==================================================")

    finally:
        # Clean up temporary test files
        print("\n[CLEANUP] Removing generated test payloads...")
        for p in [
            test_doc_path, sealed_zip, tampered_sig_zip, tampered_ots_zip, 
            missing_pub_zip, missing_sig_zip, duplicate_enc_zip, duplicate_ots_zip
        ]:
            if p.exists():
                os.remove(p)

if __name__ == "__main__":
    run_tests()
