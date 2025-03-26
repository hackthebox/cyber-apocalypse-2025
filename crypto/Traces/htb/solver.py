from pwn import *
import re
from pwn import xor

def xor_all(known, off):
    for i, enc in enumerate(enc_data):
        mn = min(len(enc_data[off]), len(enc), len(known))
        print(i, xor(enc_data[off], enc, known)[:mn])

def xor_all_with_key(key):
    for i, enc in enumerate(enc_data):
        mn = min(len(key), len(enc))
        print(i, xor(enc, key)[:mn])

if len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    io = remote(host, port, level='debug')
else:
    io = process(['python', 'challenge/server.py'], level='debug')

io.sendlineafter(b'> ', b'join #general')

raw_response = io.recvuntil(b'guest > ').strip().decode()

enc_data = list(map(bytes.fromhex, re.findall(r'[\da-f]{6,}', raw_response)))

known = b'!nick Runeblight'
# xor_all(known, 2)
# exit()
known = b'Hold on. I\'m seeing '
# xor_all(known, 14)
known = b"Here is the passphrase "
# xor_all(known, 7)
known = b"Not yet, but I'm checking "
# xor_all(known, 5)
known = b"Understood. I'm disconnecting"
# xor_all(known, 17)
known = b'Understood. Has there been any '
# xor_all(known, 4)
known = b"I'll compare the latest data with "
# xor_all(known, 12)
known = b'Agreed. Move all talks to the private '
# xor_all(known, 16)
known = "I'm checking our logs to be sure no trace"
# xor_all(known, 10)
known = b"We've got a new tip about the rebels. Let's "
# xor_all(known, 3)
known = b"We can't take any risks. Let's leave this channel"
# xor_all(known, 15)
known = b'Got it. Only share it with our most trusted allies'
# xor_all(known, 8)
known = b'Understood. Has there been any sign of them regrouping'
# xor_all(known, 4)
known = b"I'm checking our logs to be sure no trace of our actions "
# xor_all(known, 10)
known = b'If everything is clear, we move to the next stage. Our goal '
# xor_all(known, 13)
known = b'Yes. Our last move may have left traces. We must be very careful'
# xor_all(known, 9)
known = b"This channel is not safe for long talks. Let's switch to our private"
# xor_all(known, 6)
known = b'Understood. Has there been any sign of them regrouping since our last '
# xor_all(known, 4)
known = b"This channel is not safe for long talks. Let's switch to our private room"
# xor_all(known, 6)
known = b"Not yet, but I'm checking some unusual signals. If they sense us, we might "
# xor_all(known, 5)
known = b'Agreed. Move all talks to the private room. Runeblight, please clear the logs'
# xor_all(known, 16)
known = b"Understood. I'm disconnecting now. If they have seen us, we must disappear immediately"
# xor_all(known, 17)

keystream = xor(known, enc_data[17])[:len(known)]

# parse the message with the passphrase
known_secret = xor(enc_data[7], keystream)[:len(enc_data[7])].decode()

passphrase = known_secret.split(': ')[1]

io.sendline(b'!nick pwned')
io.sendlineafter(b'<pwned> : ', b'!leave')
io.sendlineafter(b'> ', f'join #secret {passphrase}'.encode())

raw_response = io.recvuntil(b'guest > ').strip().decode()

enc_data = list(map(bytes.fromhex, re.findall(r'[\da-f]{6,}', raw_response)))

# xor_all_with_key(keystream)

known = b'Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing '
# xor_all(known, 9)
known = b'We should keep our planning here. The outer halls are not secure, and too many eyes watch the '
# xor_all(known, 3)
known = b"I've been studying the traces left behind by our previous incantations, and something feels wrong"
# xor_all(known, 5)
known = b"Agreed. The enemy's scouts grow more persistent. If they catch even a whisper of our designs, they "
# xor_all(known, 4)
known = b'Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location'
# xor_all(known, 9)
known = b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network "
# xor_all(known, 5)
known = b'Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses'
# xor_all(known, 11)
known = b'Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location. It is '
# xor_all(known, 9)
known = b"I'm already cross-checking our spellwork against the ancient records. If this beacon was part of an older enchantment"
# xor_all(known, 6)
known = b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers'
# xor_all(known, 8)
known = b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept '
# xor_all(known, 12)
known = b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest "
# xor_all(known, 7)
known = b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could '
# xor_all(known, 8)
known = b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake"
# xor_all(known, 7)
known = b'Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses. We must act soon before '
# xor_all(known, 11)
known = b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals "
# xor_all(known, 5)
known = b'Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never be spoken of openly. If the enemy '
# xor_all(known, 10)
known = b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom out"
# xor_all(known, 7)
known = b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our words. We must not take '
# xor_all(known, 12)
known = b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could lose access to their '
# xor_all(known, 8)
known = b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals to an unknown "
# xor_all(known, 5)
known = b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom our entire "
# xor_all(known, 7)
known = b'Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses. We must act soon before our window of opportunity '
# xor_all(known, 11)
known = b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom our entire campaign."
# xor_all(known, 7)
known = b"Agreed. The enemy's scouts grow more persistent. If they catch even a whisper of our designs, they will move against us. We must not allow their seers or spies to track "
# xor_all(known, 4)
known = b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our words. We must not take that chance. Let this '
# xor_all(known, 12)
known = b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could lose access to their strongholds. Do we have '
# xor_all(known, 8)
known = b'Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never be spoken of openly. If the enemy ever learns of it, we will have '
# xor_all(known, 10)
known = b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our words. We must not take that chance. Let this be the '
# xor_all(known, 12)
known = b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals to an unknown beacon-one that none of "
# xor_all(known, 5)

keystream = xor(known, enc_data[5])[:len(known)]

flag_message = xor(keystream, enc_data[9]).decode()

flag = flag_message.split(': ')[1]

print(flag)
