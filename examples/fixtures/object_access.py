"""Synthetic ownership example; callers are trusted harness-supplied identities.

There is deliberately no HTTP server, persistence, authentication, or network I/O.
The insecure function is retained solely to demonstrate a regression precondition.
"""

NOTES = {
    "alice-note": {"owner": "alice", "text": "Synthetic Alice note"},
    "bob-note": {"owner": "bob", "text": "Synthetic Bob note"},
}


def insecure_get_note(caller, note_id):
    """Deliberately vulnerable: ignores caller identity."""
    return dict(NOTES[note_id])


def secure_get_note(caller, note_id):
    """Illustrative fix for this fixture's single ownership requirement."""
    note = NOTES.get(note_id)
    if note is None or note["owner"] != caller:
        raise PermissionError("Note unavailable")
    return dict(note)
