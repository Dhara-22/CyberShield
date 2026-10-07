import sqlite3


def _build_demo_db():
    """Create a tiny isolated database used only by the SQL Injection simulator."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE demo_users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    conn.executemany(
        "INSERT INTO demo_users (username, password, role) VALUES (?, ?, ?)",
        [
            ("alice", "alice123", "Student"),
            ("bob", "bob123", "Student"),
            ("admin", "admin123", "Administrator"),
        ],
    )
    conn.commit()
    return conn


def vulnerable_query(username, password):
    """Intentionally unsafe query for the local educational simulator only."""
    conn = _build_demo_db()
    try:
        # Deliberately unsafe string concatenation so the simulator can demonstrate SQLi.
        query = (
            "SELECT id, username, role FROM demo_users "
            "WHERE username = '" + username + "' AND password = '" + password + "'"
        )
        rows = conn.execute(query).fetchall()
        return [dict(row) for row in rows], query
    finally:
        conn.close()


def secure_query(username, password):
    """Safe version using a parameterized SQL query."""
    conn = _build_demo_db()
    try:
        query = (
            "SELECT id, username, role FROM demo_users "
            "WHERE username = ? AND password = ?"
        )
        rows = conn.execute(query, (username, password)).fetchall()
        return [dict(row) for row in rows], query
    finally:
        conn.close()


def simulate_sql_injection(username, password):
    """Run the same username/password through vulnerable and secure versions and compare results."""
    try:
        vulnerable_rows, vulnerable_sql = vulnerable_query(username, password)
    except sqlite3.Error as exc:
        vulnerable_rows = []
        vulnerable_sql = "The vulnerable query produced a database error."
        vulnerable_error = str(exc)
    else:
        vulnerable_error = None

    secure_rows, secure_sql = secure_query(username, password)

    # A difference in returned records is treated as evidence that the input altered
    # the vulnerable query in this small, isolated educational database.
    injection_detected = len(vulnerable_rows) > len(secure_rows)

    return {
        "status": "VULNERABLE" if injection_detected else "BLOCKED",
        "injection_detected": injection_detected,
        "vulnerable_rows": vulnerable_rows,
        "secure_rows": secure_rows,
        "vulnerable_sql": vulnerable_sql,
        "secure_sql": secure_sql,
        "vulnerable_error": vulnerable_error,
        "lesson": (
            "The vulnerable query treated part of the input as SQL. "
            "The secure parameterized query treated the same input as data."
            if injection_detected
            else "No SQL injection effect was demonstrated. Parameterized queries keep the input as data."
        ),
    }
