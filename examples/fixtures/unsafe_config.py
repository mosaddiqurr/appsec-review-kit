"""Synthetic configuration data; no application or debug listener is started."""

UNSAFE_CONFIG = {"environment": "production", "debug": True}
SYNTHETIC_MARKER = "SYNTHETIC-NOT-A-CREDENTIAL"


def production_config(debug=False):
    """Reject debug mode for this simplified production profile."""
    if debug:
        raise ValueError("Debug mode is disallowed in the production profile")
    return {"environment": "production", "debug": False}
