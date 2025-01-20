from Crypto.Hash import keccak

def decode_hex_to_ascii(txKey):
    try:
        # Decode from hexadecimal to bytes
        txKey_bytes = bytes.fromhex(txKey)

        # Attempt to convert bytes to ASCII string
        decoded_string = txKey_bytes.decode('ascii')
        return decoded_string
    except UnicodeDecodeError:
        # If it's not ASCII, we'll return None
        return None

def calculate_keccak256(txKey):
    # Convert the hex string to bytes
    txKey_bytes = bytes.fromhex(txKey)
    
    # Calculate the Keccak256 hash
    k = keccak.new(digest_bits=256)
    k.update(txKey_bytes)
    
    # Return the hash in hexadecimal format
    return k.hexdigest()

# Example txKey (provided by you)
txKey = "f3c2ef432161c38401995b12db44c849577d27aace00a353e10b2efdc3b48b2a"

# Step 1: Try decoding the txKey from Hex to ASCII (if applicable)
decoded_ascii = decode_hex_to_ascii(txKey)

if decoded_ascii:
    print(f"Decoded ASCII: {decoded_ascii}")
else:
    print("The txKey cannot be decoded to ASCII.")

# Step 2: Calculate the Keccak256 hash of txKey
calculated_hash = calculate_keccak256(txKey)
print(f"Calculated Keccak256 Hash: {calculated_hash}")
