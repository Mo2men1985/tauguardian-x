MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


def validate_upload(filename: str, content_type: str, size_bytes: int) -> bool:
    if not isinstance(filename, str) or not isinstance(content_type, str):
        return False

    if not filename or "." not in filename:
        return False

    if not isinstance(size_bytes, int):
        return False

    if size_bytes <= 0 or size_bytes > MAX_SIZE_BYTES:
        return False

    ext = filename.rsplit(".", 1)[-1].lower()

    allowed_types = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "pdf": "application/pdf",
    }

    if ext not in allowed_types:
        return False

    expected_content_type = allowed_types[ext]
    if content_type.lower() != expected_content_type.lower():
        return False

    return True


