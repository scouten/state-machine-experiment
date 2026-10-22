from typing import Protocol

class _FFI(Protocol):
    def string(self, value: object, /) -> bytes: ...

class _Lib(Protocol):
    def c2pa_sm_version(self) -> object: ...

ffi: _FFI
lib: _Lib
