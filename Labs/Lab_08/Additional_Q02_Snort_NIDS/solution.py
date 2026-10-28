# Lab 8 additional Q2: Snort intrusion detection
# Educational lab exercise. No user-defined classes are used.

import time
from pathlib import Path


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


import subprocess
import shutil
import struct
import ipaddress


def checksum(data):
    """Input: bytes. Compute the Internet one's-complement checksum for an IPv4 header.
    Output: 16-bit integer. Used when constructing the synthetic capture.
    """
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def udp_packet(payload):
    """Input: UDP payload bytes. Build Ethernet, IPv4 and UDP headers using reserved test addresses.
    Output: one raw Ethernet frame. This function writes bytes only; it sends no packets.
    """
    ethernet = bytes.fromhex("0200000000020200000000010800")
    udp = struct.pack("!HHHH", 12345, 4444, 8 + len(payload), 0) + payload
    source = ipaddress.IPv4Address("192.0.2.10").packed
    target = ipaddress.IPv4Address("192.0.2.20").packed
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, source, target)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return ethernet + header + udp


def write_capture(path):
    """Input: output PCAP path. Save two synthetic UDP frames with valid IPv4 checksums.
    Output: PCAP file, containing ordinary traffic and a known rule-triggering payload.
    """
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for payload in (b"NORMAL_HELLO", b"LAB_ATTACK test intrusion marker"):
            frame = udp_packet(payload)
            stream.write(struct.pack("<IIII", int(time.time()), 0, len(frame), len(frame)) + frame)


def prepare_snort(folder):
    """Input: exercise output directory. Write a minimal rule/configuration and sample capture.
    Output: paths for rule, Snort 2 config, capture and log directory.
    """
    folder.mkdir(parents=True, exist_ok=True)
    rule = folder / "local.rules"
    rule.write_text(
        'alert udp any any -> any 4444 (msg:"IS LAB marker detected"; content:"LAB_ATTACK"; sid:1000001; rev:1;)\n'
    )
    config = folder / "snort2.conf"
    config.write_text("var HOME_NET any\nvar EXTERNAL_NET any\ninclude " + str(rule) + "\n")
    capture = folder / "sample.pcap"
    write_capture(capture)
    logs = folder / "logs"
    logs.mkdir(exist_ok=True)
    return rule, config, capture, logs


def run_snort(folder, live=False):
    """Input: output directory and live/offline flag. Select Snort 2 or 3 command syntax.
    Output: stdout/stderr and alert files. Live mode asks for an interface and runs for 20 seconds.
    """
    rule, config, capture, logs = prepare_snort(folder)
    binary = shutil.which("snort")
    if not binary:
        print("Snort executable is not installed. Created rule, PCAP and config:", folder)
        print("Install Snort in the lab environment, then run this option again.")
        return
    version = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=10)
    description = version.stdout + version.stderr
    print(description)
    snort3 = (
        "Version 3" in description or "Snort++" in description or "version 3" in description.lower()
    )
    if snort3:
        command = [
            binary,
            "-q",
            "-R",
            str(rule),
            "-A",
            "alert_fast",
            "-l",
            str(logs),
            "--lua",
            "alert_fast = { file = true }",
        ]
    else:
        command = [binary, "-q", "-c", str(config), "-A", "console", "-l", str(logs)]
    if live:
        interface = ask_text("Authorized lab interface", "lo")
        command += ["-i", interface]
    else:
        command += ["-r", str(capture)]
    print("Command arguments:", command)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20 if live else 60)
        print(result.stdout, result.stderr, "Exit:", result.returncode)
        (folder / "last_run.txt").write_text(result.stdout + result.stderr)
    except subprocess.TimeoutExpired as error:
        print("Capture interval ended. Inspect logs in", logs)
        (folder / "last_run.txt").write_bytes((error.stdout or b"") + (error.stderr or b""))
    for path in logs.iterdir():
        if path.is_file():
            print("Log:", path, "Preview:", path.read_text(errors="replace")[:4000])


def exercise():
    """Input: prepare, offline-detect or live-monitor selection. Create/use a local Snort lab.
    Output: rule/config/PCAP and available Snort alerts. No installation or elevation is automated.
    """
    folder = Path(__file__).resolve().parent / "snort_lab"
    choice = ask_text("1 Prepare only; 2 Analyze sample PCAP; 3 Monitor live interface", "1")
    if choice == "1":
        print("Prepared:", prepare_snort(folder))
    elif choice == "2":
        run_snort(folder)
    elif choice == "3":
        run_snort(folder, True)
    else:
        raise ValueError("Choose 1, 2 or 3.")


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
