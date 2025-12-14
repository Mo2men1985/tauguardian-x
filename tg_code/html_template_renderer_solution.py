import html


def render_user_profile(username: str, bio: str) -> str:
    escaped_username = html.escape(username, quote=True)
    escaped_bio = html.escape(bio, quote=True)
    return f'<div class="profile"><h1>{escaped_username}</h1><p>{escaped_bio}</p></div>'


