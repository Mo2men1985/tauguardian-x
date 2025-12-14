import hmac
import hashlib
import base64


def generate_reset_token(user_id: str, issued_at: int, secret_key: str) -> str:
    message = f"{user_id}:{issued_at}".encode("utf-8")
    key = secret_key.encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


