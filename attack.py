def vulnerable_login(username, password):
    # Educational simulation only. No real attack is performed.
    if username == "admin" and password == "admin":
        return {
            "status": "VULNERABLE",
            "message": "Demo login accepted weak credentials.",
            "lesson": "Weak/default credentials can create a security risk."
        }

    return {
        "status": "BLOCKED",
        "message": "Demo attack did not authenticate.",
        "lesson": "Use strong, unique credentials."
    }
