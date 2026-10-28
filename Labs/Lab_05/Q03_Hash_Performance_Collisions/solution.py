# Lab 5 Q3: MD5, SHA-1 and SHA-256 experiment
# Educational lab exercise. No user-defined classes are used.

import time
import secrets
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


def generate_dataset(count, length=32):
    """Input: number of unique strings and characters per string. Generate random ASCII text.
    Output: sorted list of unique strings. Duplicate input strings are deliberately removed.
    """
    import string

    values = set()
    while len(values) < count:
        values.add(
            "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        )
    return sorted(values)


def detect_collisions(strings, algorithm):
    """Input: strings and hashlib algorithm name. Map digests to their first distinct input.
    Output: list of (first input, second input, digest) collisions; repeats are not collisions.
    """
    seen = {}
    collisions = []
    for text in strings:
        digest = hashlib.new(algorithm, text.encode()).hexdigest()
        if digest in seen and seen[digest] != text:
            collisions.append((seen[digest], text, digest))
        else:
            seen[digest] = text
    return collisions


def exercise():
    """Input: dataset count in 50..100 and repeat count. Compare the three digest algorithms.
    Output: sample digests, mean dataset hashing time and observed distinct-input collisions.
    """
    values = generate_dataset(ask_int("Number of strings", 75, 50, 100))
    repeats = ask_int("Timing repetitions", 100, 1, 10000)
    for algorithm in ("md5", "sha1", "sha256"):
        start = time.perf_counter()
        for _ in range(repeats):
            for text in values:
                hashlib.new(algorithm, text.encode()).digest()
        elapsed = (time.perf_counter() - start) / repeats
        collisions = detect_collisions(values, algorithm)
        print(algorithm, "sample digest:", hashlib.new(algorithm, values[0].encode()).hexdigest())
        print("Mean dataset time s:", elapsed, "Observed collisions:", collisions)
    print(
        "No observed collisions in a small random sample is not evidence of cryptographic collision resistance."
    )


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
