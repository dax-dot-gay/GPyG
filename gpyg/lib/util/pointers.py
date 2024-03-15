from typing import Any, Callable, Literal, TypeVar
from gpyg import gpgme

NEW_FMT = "new_{handle}_p"
COPY_FMT = "copy_{handle}_p"
DELETE_FMT = "delete_{handle}_p"
ASSIGN_FMT = "{handle}_p_assign"
VALUE_FMT = "{handle}_p_value"

TPointer = TypeVar("TPointer")
HANDLES = Literal[
    "gpgme_ctx_t",
    "gpgme_data_t",
    "gpgme_key_t",
    "gpgme_error_t",
    "gpgme_trust_item_t",
    "gpgme_engine_info_t",
]


class CPointer[TPointer]:
    @staticmethod
    def _new(handle: HANDLES) -> Any:
        return CPointer[TPointer]._func(handle, NEW_FMT)()

    @staticmethod
    def _func(handle: HANDLES, fmt: str) -> Callable:
        func = getattr(gpgme, fmt.format(handle=handle), None)
        if func == None:
            raise NotImplementedError()
        else:
            return func

    @classmethod
    def new(cls, handle: HANDLES) -> "CPointer[TPointer]":
        return cls(handle, CPointer._new(handle))

    def __init__(self, handle: HANDLES, pointer: Any):
        self.handle = handle
        self.pointer = pointer

    @property
    def value(self) -> TPointer:
        return CPointer[TPointer]._func(self.handle, VALUE_FMT)(self.pointer)

    def copy(self) -> "CPointer[TPointer]":
        return CPointer[TPointer](
            self.handle, CPointer[TPointer]._func(self.handle, COPY_FMT)(self.value)
        )

    def delete(self) -> None:
        CPointer[TPointer]._func(self.handle, DELETE_FMT)(self.pointer)

    def assign(self, value: TPointer) -> None:
        CPointer[TPointer]._func(self.handle, ASSIGN_FMT)(self.pointer, value)
