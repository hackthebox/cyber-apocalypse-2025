def affine(sentence, key_a, key_b):
    ciphertext = []
    #encode each word
    for word in sentence.split(" "):
        encoded = ""
        for i in range(len(word)):
            #apply affine cipher to each character
            apbt = "abcdefghijklmnopqrstuvwxyz"
            encoded = encoded + chr((apbt.index(word[i]) * key_a + key_b) % 26 + ord('a'))
        ciphertext.append(encoded)
    #join ciphertext
    return (" ").join(ciphertext)
#input plaintext and keys
plaintext, key_a, key_b = input().split(";")
#print answer
print(affine(plaintext, int(key_a), int(key_b)))
