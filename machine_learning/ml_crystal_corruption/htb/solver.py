import torch
import numpy as np
import struct
import hashlib

def stego_decode(tensor, n=3):

    # Extract n least significant bits from the low byte of each float in the tensor
    bits = np.unpackbits(tensor.view(dtype=np.uint8))
    
    # Reassemble the bit stream to bytes
    payload = np.packbits(np.concatenate([np.vstack(tuple([bits[i::tensor.dtype.itemsize * 8] for i in range(8-n, 8)])).ravel("F")])).tobytes()

    try:
        # Parse the size and SHA256
        (size, checksum) = struct.unpack("i 64s", payload[:68])

        # Ensure the message size is somewhat sane
        if size < 0 or size > (np.prod(tensor.shape) * n) / 8:
            return None
    except struct.error:
        return None

    # Extract the message
    message = payload[68:68+size]

    return message

def decode_payload(model_path):
    # Load the modified model from disk
    modified_model = torch.load(model_path, map_location=torch.device("cpu"))

    # Extract the tensors from the model's parameters
    for name, param in modified_model.items():
        # Convert the tensor to numpy array
        tensor_np = param.numpy()

        # Attempt to decode the payload from the tensor
        decoded_message = stego_decode(tensor_np)
        if decoded_message is not None:
            print("Decoded Message:", decoded_message.decode("utf-8"))
            return

    print("No payload found in the model.")

# Path to the modified model file
model_path = "resnet18.pth"

# Decode the payload from the modified model
decode_payload(model_path)
