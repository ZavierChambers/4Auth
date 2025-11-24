import sqlite3
from pathlib import Path
from typing import Optional

DB_PATH = "users.db"


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    db_file = Path(db_path)
    if not db_file.exists():
        raise SystemExit(f"[!] Database file not found: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def print_row_table(rows):
    if not rows:
        print("\n[No results]\n")
        return

    # Decide which columns to show in summary view
    headers = ["id", "ts_utc", "username", "action", "success", "detail"]
    col_widths = {h: len(h) for h in headers}

    # Compute max width
    for row in rows:
        for h in headers:
            val = row[h]
            text = "" if val is None else str(val)
            # Truncate detail in main listing
            if h == "detail" and len(text) > 50:
                text = text[:47] + "..."
            col_widths[h] = max(col_widths[h], len(text))

    # Separator
    sep = "+".join("-" * (col_widths[h] + 2) for h in headers)
    sep = f"+{sep}+"

    # Header row
    print("\n" + sep)
    header_line = "| " + " | ".join(h.ljust(col_widths[h]) for h in headers) + " |"
    print(header_line)
    print(sep)

    # Data rows
    for row in rows:
        line_parts = []
        for h in headers:
            val = row[h]
            text = "" if val is None else str(val)
            if h == "detail" and len(text) > 50:
                text = text[:47] + "..."
            line_parts.append(text.ljust(col_widths[h]))
        print("| " + " | ".join(line_parts) + " |")
    print(sep + "\n")


def fetch_logs(
    conn: sqlite3.Connection,
    username: Optional[str] = None,
    action: Optional[str] = None,
    success: Optional[bool] = None,
    limit: int = 50,
) -> list[sqlite3.Row]:
    query = "SELECT id, ts_utc, username, action, success, detail FROM access_logs"
    clauses = []
    params = []

    if username:
        clauses.append("username = ?")
        params.append(username)

    if action:
        clauses.append("action = ?")
        params.append(action)

    if success is not None:
        clauses.append("success = ?")
        params.append(1 if success else 0)

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cur = conn.execute(query, params)
    return cur.fetchall()


def fetch_log_by_id(conn: sqlite3.Connection, log_id: int) -> Optional[sqlite3.Row]:
    cur = conn.execute(
        "SELECT id, ts_utc, username, action, success, detail FROM access_logs WHERE id = ?",
        (log_id,),
    )
    row = cur.fetchone()
    return row


def view_recent(conn: sqlite3.Connection):
    try:
        limit = int(input("Show how many recent entries? [default 20]: ") or "20")
    except ValueError:
        limit = 20
    rows = fetch_logs(conn, limit=limit)
    print_row_table(rows)


def view_by_username(conn: sqlite3.Connection):
    username = input("Username to filter by: ").strip()
    if not username:
        print("No username entered.")
        return
    try:
        limit = int(input("Max rows [default 50]: ") or "50")
    except ValueError:
        limit = 50
    rows = fetch_logs(conn, username=username, limit=limit)
    print_row_table(rows)


def view_by_action(conn: sqlite3.Connection):
    action = input("Action to filter by (e.g. login, register, recover_totp): ").strip()
    if not action:
        print("No action entered.")
        return
    try:
        limit = int(input("Max rows [default 50]: ") or "50")
    except ValueError:
        limit = 50
    rows = fetch_logs(conn, action=action, limit=limit)
    print_row_table(rows)


def view_by_success(conn: sqlite3.Connection, success: bool):
    label = "successful" if success else "failed"
    try:
        limit = int(input(f"Max rows of {label} events [default 50]: ") or "50")
    except ValueError:
        limit = 50
    rows = fetch_logs(conn, success=success, limit=limit)
    print_row_table(rows)


def view_single_log(conn: sqlite3.Connection):
    try:
        log_id = int(input("Enter log ID: ").strip())
    except ValueError:
        print("Invalid ID.")
        return
    row = fetch_log_by_id(conn, log_id)
    if not row:
        print("No log entry with that ID.")
        return

    print("\n=== Log Entry Details ===")
    print(f"ID      : {row['id']}")
    print(f"Time    : {row['ts_utc']}")
    print(f"User    : {row['username']}")
    print(f"Action  : {row['action']}")
    print(f"Success : {row['success']}")
    print(f"Detail  :\n{row['detail']}\n")


def main():
    print(r"""
   __ __  ___         __  __       __                   _    ___                       
  / // / /   | __  __/ /_/ /_     / /   ____  ____ _   | |  / (_)__ _      _____  _____
 / // /_/ /| |/ / / / __/ __ \   / /   / __ \/ __ `/   | | / / / _ \ | /| / / _ \/ ___/
/__  __/ ___ / /_/ / /_/ / / /  / /___/ /_/ / /_/ /    | |/ / /  __/ |/ |/ /  __/ /    
  /_/ /_/  |_\__,_/\__/_/ /_/  /_____/\____/\__, /     |___/_/\___/|__/|__/\___/_/     
                                           /____/                                         
    """)
    print("4Auth Log Viewer - reading from:", DB_PATH)

    conn = get_connection()

    while True:
        print(
            "\nMenu:\n"
            "1. View most recent logs\n"
            "2. Filter by username\n"
            "3. Filter by action\n"
            "4. View only successful events\n"
            "5. View only failed events\n"
            "6. View a single log entry by ID\n"
            "7. Exit\n"
        )
        choice = input("> ").strip()

        if choice == "1":
            view_recent(conn)
        elif choice == "2":
            view_by_username(conn)
        elif choice == "3":
            view_by_action(conn)
        elif choice == "4":
            view_by_success(conn, True)
        elif choice == "5":
            view_by_success(conn, False)
        elif choice == "6":
            view_single_log(conn)
        elif choice == "7":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
