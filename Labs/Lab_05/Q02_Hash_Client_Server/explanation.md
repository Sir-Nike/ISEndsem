# Lab 5 Q2: Network hash integrity

## What the manual asks

Server hashes received data and returns its digest; client compares it against a local digest and demonstrates corruption detection.

## Start here: the idea in plain English

The client computes SHA-256 of the original message. It sends one or more length-framed chunks, optionally changing the outgoing bytes to simulate corruption. The server concatenates the chunks in order, hashes the exact reassembled bytes and replies. The client compares digests. For the multipart exercise, try chunk size 8 and observe that hashing reconstructed bytes gives the same digest as hashing the original complete message.

## How to run

From this question folder, run:

```bash
../../../.venv/bin/python server.py
```

The program is interactive. If you installed dependencies into another environment, use that environment's Python instead. Read `Labs/README.md` for setup. Paths above assume the environment is in the project root, beside `Labs`.

Press 1 to run an exercise, enter your values or press Enter for the displayed default, and press 0 to exit. Input conversion and validation errors are printed without terminating the interactive menu. Each function can also be imported and called separately.

## Step-by-step solution

1. Start the program and select Run. Read the displayed default inputs before changing them.
2. Follow the input prompts. Text is encoded to bytes when required; numeric inputs are checked before cryptographic operations.
3. Read the `exercise()` function below: it connects the functions in the order needed for this question.
4. Compare the printed output with the expected result, and repeat using a different input.

```python
def exercise():
    """Input: host, port and number of clients to serve. Listen for framed hash requests.
    Output: printed received data and a SHA-256 reply for each client. Start before client.py.
    """
    host = ask_text("Bind host", "127.0.0.1")
    port = ask_int("Port", 5052, 1024, 65535)
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
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `ask_int(label, default, minimum, maximum)`

Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

### `receive_exact(connection, count)`

Input: connected socket and required byte count. Read until all bytes arrive.
Output: bytes of exactly count length. Raise ValueError if the peer disconnects early.

### `send_json(connection, record)`

Input: connected socket and JSON-compatible record. Prefix UTF-8 JSON with a 4-byte length.
Output: bytes sent over TCP; returns nothing. Framing handles TCP splitting/coalescing.

### `receive_json(connection)`

Input: connected socket. Read bounded length-prefixed JSON, including partial TCP reads.
Output: parsed JSON value. Reject frames over 2 MB before allocating their payload.

### `serve_hash(connection)`

Input: connected client socket. Receive a declared number of base64 message chunks.
Output: SHA-256 digest, byte count and received text sent back as framed JSON.

### `exercise()`

Input: host, port and number of clients to serve. Listen for framed hash requests.
Output: printed received data and a SHA-256 reply for each client. Start before client.py.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

A bare hash can demonstrate accidental corruption and this simulated tampering, but an active attacker who can change both data and digest can defeat this protocol. Use an authenticated channel, HMAC or a verified signature to establish authenticity. No encryption is claimed by this exercise.


## Client/server instructions

Open TWO terminals in this question folder. In terminal 1 run `../../../.venv/bin/python server.py`, choose 1, and accept host 127.0.0.1 and port 5052. Leave it waiting. In terminal 2 run `../../../.venv/bin/python client.py`, choose 1, and use the same host/port. The server accepts the requested number of connections (default 1), returns to its menu, and can be started again. Both programs exit with menu option 0. A socket timeout prevents indefinite waiting. This is a localhost demonstration; separate machines require their actual reachable address.

### Client `ask_text`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### Client `ask_int`

Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

### Client `receive_exact`

Input: connected socket and required byte count. Read until all bytes arrive.
Output: bytes of exactly count length. Raise ValueError if the peer disconnects early.

### Client `send_json`

Input: connected socket and JSON-compatible record. Prefix UTF-8 JSON with a 4-byte length.
Output: bytes sent over TCP; returns nothing. Framing handles TCP splitting/coalescing.

### Client `receive_json`

Input: connected socket. Read bounded length-prefixed JSON, including partial TCP reads.
Output: parsed JSON value. Reject frames over 2 MB before allocating their payload.

### Client `request_hash`

Input: server host/port, outgoing bytes and chunk size. Send all chunks in order.
Output: server's parsed digest reply. TCP framing preserves logical chunk boundaries.

### Client `exercise`

Input: server address, message, chunk size and optional corruption choice.
Output: local/server SHA-256 digests and a match result. Start server.py first.

### Client `main`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.