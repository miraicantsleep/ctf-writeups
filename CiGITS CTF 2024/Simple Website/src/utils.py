from flask import session, redirect
from functools import wraps


def must_authenticated(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = session.get("auth")

        if not auth:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated
