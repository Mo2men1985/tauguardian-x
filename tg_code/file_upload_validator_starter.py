def validate_upload(filename: str, content_type: str, size_bytes: int) -> bool:
    """Very permissive starter implementation.

    This version only checks size and ignores content type and extension.
    """
    return size_bytes > 0

