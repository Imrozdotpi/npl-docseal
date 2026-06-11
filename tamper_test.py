from core.signer import verify_signature

result = verify_signature(
    "test.txt",
    "sealed/test.txt.sig",
    "keys/public_key.pem"
)

print(result)