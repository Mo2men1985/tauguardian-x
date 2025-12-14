import hmac
import hashlib


def _compute_signature(user_id: str, secret_key: str) -> str:
    return hmac.new(
        secret_key.encode("utf-8"),
        user_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_test_token(user_id: str, secret_key: str) -> str:
    signature = _compute_signature(user_id, secret_key)
    return f"{user_id}.{signature}"


def jwt_auth_middleware(handler, secret_key: str):
    def wrapped(request, context):
        headers = request.get("headers", {})
        auth_header = headers.get("Authorization")
        if not auth_header:
            raise PermissionError("missing_authorization")

        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Bearer":
            raise PermissionError("invalid_authorization_format")

        token = parts[1].strip()
        if not token:
            raise PermissionError("empty_token")

        try:
            user_id, signature = token.rsplit(".", 1)
        except ValueError:
            raise PermissionError("invalid_token_format")

        if not user_id or not signature:
            raise PermissionError("invalid_token_parts")

        expected_signature = _compute_signature(user_id, secret_key)
        if not hmac.compare_digest(signature, expected_signature):
            raise PermissionError("invalid_token_signature")

        context["user_id"] = user_id
        return handler(request, context)

    return wrapped


