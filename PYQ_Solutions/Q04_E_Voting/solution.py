from crypto_helpers import ask_text


def main():
    """Input: terminal role/entry selection. Launch server, voter client or single-trustee utility.
    Output: chosen program's normal interactive menu. Use separate terminals for server and client.
    """
    while True:
        print("\n1 Election server  2 Voter client  3 Trustee utility  0 Exit")
        choice = ask_text("Choice")
        if choice == "0":
            return
        try:
            if choice == "1":
                from server import main as run_server

                run_server()
            elif choice == "2":
                from client import main as run_client

                run_client()
            elif choice == "3":
                from trustee import main as run_trustee

                run_trustee()
            else:
                print("Choose a listed option.")
        except (ValueError, KeyError, TypeError, PermissionError, OSError) as error:
            print("Rejected:", error)


if __name__ == "__main__":
    main()
