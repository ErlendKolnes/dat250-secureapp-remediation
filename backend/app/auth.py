import hashlib
import secrets
import bcrypt
from fastapi import Request
from app.database import run_query


def hash_password(password: str) -> str:
    # Secure password storage (Funn 4): bcrypt is salted and deliberately slow,
    # unlike the previous unsalted SHA-256.
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _is_bcrypt(password_hash: str) -> bool:
    return password_hash.startswith(("$2a$", "$2b$", "$2y$"))


def verify_password(password: str, password_hash: str) -> bool:
    # Accept bcrypt hashes. Legacy unsalted SHA-256 hashes (from the original seed
    # data) are still verified so existing users can log in; they are upgraded to
    # bcrypt on next successful login (see auth_routes.login).
    if _is_bcrypt(password_hash):
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return legacy == password_hash


def needs_rehash(password_hash: str) -> bool:
    return not _is_bcrypt(password_hash)


def create_session(user_id: int) -> str:
    token = secrets.token_hex(16)
    run_query(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, token),
        commit=True,
    )
    return token


def get_user_from_session(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None
    session = run_query(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token = %s
        """,
        (session_token,),
        fetchone=True,
    )
    return session


def clear_session(token: str):
    run_query("DELETE FROM sessions WHERE session_token = %s", (token,), commit=True)
