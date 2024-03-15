from gpyg.gpgme import GpgErr


class GPGError(Exception):
    pass


class GPGInternalError(GPGError):
    def __init__(self, error: GpgErr | int, *args: object) -> None:
        self.error = GpgErr(error)
        super().__init__(*args)

    def __str__(self) -> str:
        return f"Encountered an internal GPG error: {repr(self.error)}. \n\n{super().__str__()}"


def raise_error(result: GpgErr | int) -> None:
    if result == GpgErr.NO_ERROR or result == None:
        return
    raise GPGInternalError(result)
