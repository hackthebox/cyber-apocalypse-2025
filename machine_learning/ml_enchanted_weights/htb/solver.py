import torch

model = SecretModel()
model.load_state_dict(torch.load("eldorian_artifact.pth"))

# Extract the diagonal weights
weights = model.hidden.weight.detach().numpy()
print(weights)
ascii_values = weights.diagonal().astype(int)

# Decode ASCII to characters
flag = ''.join(chr(x) for x in ascii_values)
print("Flag:", flag)