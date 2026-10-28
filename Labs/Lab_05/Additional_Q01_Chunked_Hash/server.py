# Lab 5 additional Q1: Chunked network hash
# Educational lab exercise. No user-defined classes are used.

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


def serve_hash(connection):
    """Input: connected client socket. Receive a declared number of base64 message chunks.
    Output: SHA-256 digest, byte count and received text sent back as framed JSON.
    """
    header = receive_json(connection)
    count = header["count"]
    if not isinstance(count, int) or not 1 <= count <= 10000:
        raise ValueError("Invalid chunk count.")
    data = bytearray()
    for _ in range(count):
        chunk = receive_json(connection)
        data.extend(base64.b64decode(chunk["data"], validate=True))
        if len(data) > 1024 * 1024:
            raise ValueError("Total message exceeds 1 MB.")
    digest = hashlib.sha256(data).hexdigest()
    send_json(
        connection, {"sha256": digest, "bytes": len(data), "text": data.decode(errors="replace")}
    )
    print("Received:", data.decode(errors="replace"), "SHA-256:", digest)


def exercise():
    """Input: host, port and number of clients to serve. Listen for framed hash requests.
    Output: printed received data and a SHA-256 reply for each client. Start before client.py.
    """
    host = ask_text("Bind host", "127.0.0.1")
    port = ask_int("Port", 5053, 1024, 65535)
    count = ask_int("Connections before returning to menu", 1, 1, 100)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        listener.settimeout(60)
        print("Listening on", host, port, flush=True)
        for _ in range(count):
            connection, address = listener.accept()
            with connection:
                connection.settimeout(15)
                try:
                    serve_hash(connection)
                except (ValueError, KeyError, OSError) as error:
                    print("Rejected client:", error)


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
