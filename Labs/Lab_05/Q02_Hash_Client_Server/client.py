# Lab 5 Q2: Network hash integrity - client

import json
import hashlib


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


def ask_int(label, default, minimum=None, maximum=None):
    """Input: prompt, default integer, optional inclusive limits. Read and validate a number.
    Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.
    """
    value = int(ask_text(label, default))
    if minimum is not None and value < minimum:
        raise ValueError(f"{label} must be at least {minimum}.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be at most {maximum}.")
    return value


import socket
import struct
import base64


def receive_exact(connection, count):
    """Input: connected socket and required byte count. Read until all bytes arrive.
    Output: bytes of exactly count length. Raise ValueError if the peer disconnects early.
    """
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise ValueError("Connection closed before a complete message arrived.")
        data.extend(part)
    return bytes(data)


def send_json(connection, record):
    """Input: connected socket and JSON-compatible record. Prefix UTF-8 JSON with a 4-byte length.
    Output: bytes sent over TCP; returns nothing. Framing handles TCP splitting/coalescing.
    """
    data = json.dumps(record).encode()
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("Frame exceeds 2 MB teaching limit.")
    connection.sendall(struct.pack("!I", len(data)) + data)


def receive_json(connection):
    """Input: connected socket. Read bounded length-prefixed JSON, including partial TCP reads.
    Output: parsed JSON value. Reject frames over 2 MB before allocating their payload.
    """
    size = struct.unpack("!I", receive_exact(connection, 4))[0]
    if size > 2 * 1024 * 1024:
        raise ValueError("Incoming frame too large.")
    return json.loads(receive_exact(connection, size))


def request_hash(host, port, data, chunk_size):
    """Input: server host/port, outgoing bytes and chunk size. Send all chunks in order.
    Output: server's parsed digest reply. TCP framing preserves logical chunk boundaries.
    """
    chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]
    with socket.create_connection((host, port), timeout=15) as connection:
        send_json(connection, {"count": len(chunks)})
        for chunk in chunks:
            send_json(connection, {"data": base64.b64encode(chunk).decode()})
        return receive_json(connection)


def exercise():
    """Input: server address, message, chunk size and optional corruption choice.
    Output: local/server SHA-256 digests and a match result. Start server.py first.
    """
    host = ask_text("Server host", "127.0.0.1")
    port = ask_int("Port", 5052, 1024, 65535)
    original = ask_text("Message", "Information Security over TCP").encode()
    chunk_size = max(1, len(original) + 1)
    if chunk_size < 1:
        raise ValueError("Chunk size must be positive.")
    corrupt = ask_text("Simulate changed outgoing data? y/n", "n").lower() == "y"
    outgoing = original + b"!" if corrupt else original
    local = hashlib.sha256(original).hexdigest()
    reply = request_hash(host, port, outgoing, chunk_size)
    print("Local digest:", local, "Server digest:", reply["sha256"])
    print("Integrity verified:", __import__("hmac").compare_digest(local, reply["sha256"]))
    print("Server reassembled:", reply["text"])


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
