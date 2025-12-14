def jwt_auth_middleware(handler, secret_key: str):
    """Starter implementation: only checks the header exists."""
    def wrapped(request, context):
        headers = request.get("headers", {})
        if "Authorization" not in headers:
            raise PermissionError("missing_authorization")
        # TODO: parse and verify token using secret_key, inject user_id into context
        return handler(request, context)
    return wrapped

