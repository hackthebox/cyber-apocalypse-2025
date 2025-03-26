import jwt

# should be extracted with dynamic analysis (or static analysis for the strong reversers out there)
jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcm9tIjoiY29zdGkiLCJjYW1wYWlnbl9pZCI6Ik9wZXJhdGlvbiBFbGRvcmlhIDogRXhwb3NpbmcgdGhlIGJyYXZlcyIsImF1dGgiOiJVMFpTUTJVd1JsRldSamxxVFVjMWVtTkVSbmxPUjAxNFRUTk9abGxxVG05TlZ6VnJXREpKZW1KcVJtNWliRGx6VFVSQ2NrMVhOVzVZTTAxNFpFUk9lbVpSUFQwPSJ9.TEbKlRUveIhkW7eAfRP7in1D6-rIpwy7GZi_Xe8TvSQ'

token = jwt.decode(jwt_token, algorithms=["HS256"], options={"verify_signature": False})

from base64 import b64decode
print(b64decode(b64decode(token['auth'].encode())).decode())
