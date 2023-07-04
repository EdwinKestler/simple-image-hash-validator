import hashlib

def calculate_hash(file_path):
    """
    Calculate the hash of a file using SHA256 algorithm.
    """
    hash_object = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_object.update(chunk)
    return hash_object.hexdigest()

def validate_image_hash(file_path, expected_hash):
    """
    Validate the hash of an image file against the expected hash value.
    """
    image_hash = calculate_hash(file_path)
    if image_hash == expected_hash:
        print("Image hash is valid.")
    else:
        print("Image hash is not valid.")

# Example usage
file_path = 'source-9ae6450d23a746fa769fa2c4d2a02a47df371d261e25e8c86b4839a79c5333b2.jpg'
expected_hash = '9ae6450d23a746fa769fa2c4d2a02a47df371d261e25e8c86b4839a79c5333b2'  # Replace with the actual expected hash
validate_image_hash(file_path, expected_hash)