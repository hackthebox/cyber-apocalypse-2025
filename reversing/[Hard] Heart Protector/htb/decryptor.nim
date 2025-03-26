import nimcrypto

proc toBytes(s: string): seq[byte] =
    return @(s.toOpenArrayByte(0, s.high))

let key = toBytes("a9060b622a6d95eb")
let AD = toBytes("HTB_CA2K25_f0r_l0rd_m4l4k4r!")

let encFileDataRaw = toBytes(readFile("heart.png.malakar"))

var IV = encFileDataRaw[0 .. 9]

var decryptContext: GCM[aes128]
decryptContext.init(key, IV, AD)

var plainText = newSeq[byte](len(encFileDataRaw)-10)

decryptContext.decrypt(encFileDataRaw[10 .. ^1], plaintext)

let Header: array[4, byte] = [137'u8, 80'u8, 78'u8, 71'u8]

if plaintext[0 .. 3] == Header:
    writeFile("heart.png", plaintext)
    echo "[+] the image was successfully decrypted"