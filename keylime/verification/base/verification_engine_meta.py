from abc import ABCMeta
from typing import Any

class VerificationEngineMeta(ABCMeta):
    def __new__(mcs, new_cls_name: str, bases: tuple[type, ...], attrs: dict[str, Any]) -> "VerificationEngineMeta":
        cls = super().__new__(mcs, new_cls_name, bases, attrs)

        registration_method = getattr(cls, "register_callbacks", None)

        if not registration_method:
            raise TypeError(f"no register_callbacks method present in class '{cls.__name__}'")

        if not callable(registration_method):
            raise TypeError(f"member 'register_callbacks' of class '{cls.__name__}' not callable")

        if not getattr(registration_method, "__isabstractmethod__", False):
            registration_method()

        return cls