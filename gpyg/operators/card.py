from typing import Any, TypedDict
from .common import BaseOperator
from ..models import SmartCard, StatusCodes
from ..util import StatusInteractive, ExecutionError


class FetchedKeyResult(TypedDict):
    id: str
    first_name: str
    last_name: str
    extras: str


class CardOperator(BaseOperator):

    def __init__(self, gpg: Any, interactive: StatusInteractive) -> None:
        super().__init__(gpg)
        self.interactive = interactive

    def debug(self):
        for i in self.interactive.readlines(yield_empty=False):
            print(i)

    @property
    def active(self) -> SmartCard | None:
        """Gets information about the current card.

        Returns:
            SmartCard | None: Card data, or None if no card is present.
        """
        result = self.session.run("gpg --with-colons --card-status")
        if result.code == 0:
            return SmartCard.from_status(result.output)
        else:
            return None

    def reset(self) -> SmartCard:
        """Resets the active card to factory settings.

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Reset card instance
        """
        self.interactive.writelines("factory-reset")
        entered = False
        success = False
        lines = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status:
                cmd = line.code
                arg = line.arguments[0] if len(line.arguments) > 0 else None
                lines.append(line.content)

                if (
                    cmd == StatusCodes.GET_BOOL
                    and arg == "cardedit.factory-reset.proceed"
                ):
                    self.interactive.writelines("y")

                elif cmd == StatusCodes.GET_LINE:
                    if arg == "cardedit.factory-reset.really":
                        self.interactive.writelines("yes")
                        success = True
                    elif arg == "cardedit.prompt":
                        if entered:
                            if success:
                                return self.active
                            else:
                                raise ExecutionError("\n".join(lines))
                        else:
                            entered = True

    def set_name(
        self, first_name: str, last_name: str, admin_pin: str = "12345678"
    ) -> SmartCard:
        """Sets the name of the cardholder

        Args:
            first_name (str): First Name
            last_name (str): Last Name
            admin_pin (str, optional): Admin PIN of card. Defaults to "12345678".

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated SmartCard
        """
        self.interactive.writelines("name")
        success = False
        lines = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status:
                lines.append(line.content)
                cmd = line.code
                arg = line.arguments[0] if len(line.arguments) > 0 else None
                if cmd == StatusCodes.GET_LINE:
                    if arg == "keygen.smartcard.surname":
                        self.interactive.writelines(last_name)
                    elif arg == "keygen.smartcard.givenname":
                        self.interactive.writelines(first_name)
                    elif arg == "cardedit.prompt":
                        if success:
                            return self.active
                        else:
                            raise ExecutionError("\n".join(lines))
                    else:
                        self.interactive.writelines("")
                elif cmd == StatusCodes.GET_HIDDEN:
                    self.interactive.writelines(admin_pin)
                elif cmd == StatusCodes.SC_OP_SUCCESS:
                    success = True

    def set_key_url(self, url: str | None, admin_pin: str = "12345678") -> SmartCard:
        """Sets the URL of the current card's public key.

        Args:
            url (str | None): URL, or None to unset
            admin_pin (str, optional): Card admin PIN. Defaults to "12345678".

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card instance
        """
        self.interactive.writelines("url")
        success = False
        lines = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status:
                lines.append(line.content)
                cmd = line.code
                arg = line.arguments[0] if len(line.arguments) > 0 else None
                if cmd == StatusCodes.GET_LINE:
                    if arg == "cardedit.change_url":
                        self.interactive.writelines(url if url else "UNSET")
                    else:
                        if success:
                            return self.active
                        else:
                            raise ExecutionError("\n".join(lines))
                elif cmd == StatusCodes.GET_HIDDEN:
                    self.interactive.writelines(admin_pin)
                elif cmd == StatusCodes.SC_OP_SUCCESS:
                    success = True

    def get_key_from_url(self) -> list[FetchedKeyResult] | None:
        """Gets the key information from the card's URL, returning None if not present.

        Returns:
            list[FetchedKeyResult] | None: List of results, or None if not present.
        """
        if not self.active.public_key_url or self.active.public_key_url == "UNSET":
            return None

        self.interactive.writelines("fetch")
        results: list[FetchedKeyResult] = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status and line.code == StatusCodes.IMPORTED:
                results.append(
                    {
                        "id": line.arguments[0],
                        "first_name": (
                            line.arguments[1] if len(line.arguments) > 1 else ""
                        ),
                        "last_name": (
                            line.arguments[2] if len(line.arguments) > 2 else ""
                        ),
                        "extras": (
                            " ".join(line.arguments[3:])
                            if len(line.arguments) > 3
                            else ""
                        ),
                    }
                )
            elif line.code == StatusCodes.GET_LINE:
                return results
