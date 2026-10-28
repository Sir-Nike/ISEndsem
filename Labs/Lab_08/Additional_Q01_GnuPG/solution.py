# Lab 8 additional Q1: GnuPG encryption and signatures
# Educational lab exercise. No user-defined classes are used.

from pathlib import Path


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


import subprocess
import shutil


def gpg_command(home, arguments, check=True):
    """Input: isolated keyring directory, list of GnuPG arguments and whether failure is fatal.
    Output: completed subprocess result. No shell is used; commands stay inside this keyring.
    """
    binary = shutil.which("gpg")
    if not binary:
        raise ValueError("GnuPG is not installed. Install gpg before this exercise.")
    command = [
        binary,
        "--homedir",
        str(home),
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
    ] + arguments
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if check and result.returncode != 0:
        raise ValueError(result.stderr)
    return result


def ensure_identity(home):
    """Input: isolated GnuPG home. Reuse its first secret identity or generate a lab RSA identity.
    Output: fingerprint string. The lab key deliberately has no passphrase for a repeatable exercise.
    """
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    listing = gpg_command(home, ["--with-colons", "--list-secret-keys"]).stdout
    if not any(line.startswith("sec:") for line in listing.splitlines()):
        gpg_command(
            home,
            [
                "--quick-generate-key",
                "IS Lab <is-lab@example.invalid>",
                "rsa2048",
                "sign,encr",
                "0",
            ],
        )
        listing = gpg_command(home, ["--with-colons", "--list-secret-keys"]).stdout
    for line in listing.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise ValueError("No GnuPG fingerprint found.")


def exercise():
    """Input: message text. Run GnuPG encrypt/decrypt and detached-signature verification.
    Output: isolated keyring, public key, encrypted/received files and tamper rejection.
    """
    folder = Path(__file__).resolve().parent / "storage"
    folder.mkdir(exist_ok=True)
    home = folder / "gnupg"
    fingerprint = ensure_identity(home)
    plain = folder / "message.txt"
    plain.write_text(ask_text("Message", "Secure GnuPG file transfer"))
    public = gpg_command(home, ["--armor", "--export", fingerprint]).stdout
    (folder / "public_key.asc").write_text(public)
    encrypted = folder / "message.gpg"
    signature = folder / "message.sig"
    gpg_command(
        home,
        [
            "--trust-model",
            "always",
            "--recipient",
            fingerprint,
            "--output",
            str(encrypted),
            "--encrypt",
            str(plain),
        ],
    )
    gpg_command(
        home, ["--local-user", fingerprint, "--output", str(signature), "--detach-sign", str(plain)]
    )
    received = folder / "received"
    received.mkdir(exist_ok=True)
    shutil.copy2(encrypted, received / encrypted.name)
    shutil.copy2(signature, received / signature.name)
    recovered = received / "message.txt"
    gpg_command(home, ["--output", str(recovered), "--decrypt", str(received / encrypted.name)])
    valid = gpg_command(home, ["--verify", str(received / signature.name), str(recovered)], False)
    tampered = received / "tampered.txt"
    tampered.write_bytes(recovered.read_bytes() + b"!")
    invalid = gpg_command(home, ["--verify", str(received / signature.name), str(tampered)], False)
    print("Public fingerprint:", fingerprint, "Recovered:", recovered.read_text())
    print(
        "Original signature valid:",
        valid.returncode == 0,
        "Tampered signature valid:",
        invalid.returncode == 0,
    )
    print("Files:", folder)


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
