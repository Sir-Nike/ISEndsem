# Lab 2 Q5: AES-192 with every round shown
# Educational lab exercise. No user-defined classes are used.



def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad


def parse_key(text, algorithm):
    """Input: key written as hex:... or text:..., plus AES/DES/3DES algorithm name.
    Output: validated key bytes. Explicit prefixes prevent hex text being misread as ASCII.
    """
    if text.startswith("hex:"):
        key = bytes.fromhex(text[4:])
    elif text.startswith("text:"):
        key = text[5:].encode()
    else:
        raise ValueError("Prefix the key with hex: or text:.")
    allowed = {"AES": (16, 24, 32), "DES": (8,), "3DES": (16, 24)}
    if len(key) not in allowed[algorithm]:
        raise ValueError(f"{algorithm} needs {allowed[algorithm]} bytes, received {len(key)}.")
    if algorithm == "3DES":
        key = DES3.adjust_key_parity(key)
    return key


def gf_multiply(a, b):
    """Input: two bytes as integers. Multiply in AES's GF(2^8) using polynomial 0x11b.
    Output: one byte integer. Used by the S-box construction and MixColumns.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        a &= 255
        b >>= 1
    return result


def make_sbox():
    """Input: none. Compute each byte's field inverse and AES affine transformation.
    Output: 256-entry S-box list. This avoids a long unexplained hardcoded table.
    """
    box = []
    for value in range(256):
        inverse = 0
        if value:
            inverse = 1
            for _ in range(254):
                inverse = gf_multiply(inverse, value)
        transformed = inverse
        for shift in (1, 2, 3, 4):
            transformed ^= ((inverse << shift) | (inverse >> (8 - shift))) & 255
        box.append(transformed ^ 0x63)
    return box


def expand_key(key, sbox):
    """Input: 24-byte AES-192 key and S-box. Expand six initial words into 52 words.
    Output: 13 round keys, each 16 bytes. Apply RotWord, SubWord and Rcon every sixth word.
    """
    if len(key) != 24:
        raise ValueError("AES-192 requires exactly 24 bytes.")
    words = [list(key[i : i + 4]) for i in range(0, 24, 4)]
    rcon = 1
    for i in range(6, 52):
        temp = words[i - 1][:]
        if i % 6 == 0:
            temp = [sbox[x] for x in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = gf_multiply(rcon, 2)
        words.append([a ^ b for a, b in zip(words[i - 6], temp)])
    return [sum(words[i : i + 4], []) for i in range(0, 52, 4)]


def encrypt_block_trace(block, key):
    """Input: one 16-byte block and 24-byte key. Print AES-192's intermediate states.
    Output: 16 ciphertext bytes. State uses AES column-major order; final round omits mixing.
    """
    if len(block) != 16:
        raise ValueError("Trace requires exactly one 16-byte block.")
    sbox = make_sbox()
    keys = expand_key(key, sbox)
    for i, k in enumerate(keys):
        print("Round key", i, bytes(k).hex())
    state = [a ^ b for a, b in zip(block, keys[0])]
    print("Initial AddRoundKey:", bytes(state).hex())
    for round_number in range(1, 13):
        state = [sbox[x] for x in state]
        print(round_number, "SubBytes:", bytes(state).hex())
        state = [state[4 * ((column + row) % 4) + row] for column in range(4) for row in range(4)]
        print(round_number, "ShiftRows:", bytes(state).hex())
        if round_number != 12:
            mixed = []
            for i in range(0, 16, 4):
                a, b, c, d = state[i : i + 4]
                mixed.extend(
                    [
                        gf_multiply(a, 2) ^ gf_multiply(b, 3) ^ c ^ d,
                        a ^ gf_multiply(b, 2) ^ gf_multiply(c, 3) ^ d,
                        a ^ b ^ gf_multiply(c, 2) ^ gf_multiply(d, 3),
                        gf_multiply(a, 3) ^ b ^ c ^ gf_multiply(d, 2),
                    ]
                )
            state = mixed
            print(round_number, "MixColumns:", bytes(state).hex())
        state = [a ^ b for a, b in zip(state, keys[round_number])]
        print(round_number, "AddRoundKey:", bytes(state).hex())
    return bytes(state)


def exercise():
    """Input: message and 24-byte key. Trace every AES block and verify with the library.
    Output: key schedule, all round states, ciphertext and recovered original message.
    """
    text = ask_text("Message", "Top Secret Data")
    key = parse_key(
        ask_text("AES-192 key", "hex:FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"), "AES"
    )
    if len(key) != 24:
        raise ValueError("This exercise specifically needs a 24-byte key.")
    data = pad(text.encode(), 16)
    output = b""
    for i in range(0, len(data), 16):
        print("Block", i // 16 + 1)
        output += encrypt_block_trace(data[i : i + 16], key)
    expected = AES.new(key, AES.MODE_ECB).encrypt(data)
    assert output == expected
    print("Ciphertext:", output.hex(), "Library agrees:", output == expected)
    print("Recovered:", unpad(AES.new(key, AES.MODE_ECB).decrypt(output), 16).decode())


def main():
    """Input: terminal choices. Run the exercise safely.
    Output: printed results. Use python solution.py and choose a menu option.
    """
    while True:
        print("\n1. Run exercise (you can change the inputs)\n0. Exit")
        choice = input("Choice: ").strip()
        if choice == "0":
            return
        if choice != "1":
            print("Choose 1 or 0.")
            continue
        try:
            exercise()
        except (ValueError, TypeError, KeyError, OSError) as error:
            print("Could not complete operation:", error)


if __name__ == "__main__":
    main()
