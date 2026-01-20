"""Authorization framework for Keylime.

This package provides a pluggable authorization system that separates
authentication (who you are) from authorization (what you can do).

The framework consists of:
- Authorization providers: Implementations that make authorization decisions
- Authorization manager: Loads and routes requests to the configured provider
- Action enum: All possible operations in Keylime
- Request/Response dataclasses: Standard format for authorization decisions
"""
