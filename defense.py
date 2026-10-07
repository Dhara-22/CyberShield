def secure_login(username, password):
    # Educational defensive simulation.
    if len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password):
        return {
            "status": "SECURE",
            "message": "Password passed the basic strength policy.",
            "lesson": "Use long passwords with mixed character types."
        }

    return {
        "status": "REJECTED",
        "message": "Password rejected by the basic security policy.",
        "lesson": "Use at least 8 characters, an uppercase letter, and a number."
    }
