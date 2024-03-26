from typing import Any, Literal, TypedDict
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

    def set_login(self, login: str, admin_pin: str = "12345678") -> SmartCard:
        self.interactive.writelines("login")
        success = False
        lines = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status:
                lines.append(line.content)
                cmd = line.code
                arg = line.arguments[0] if len(line.arguments) > 0 else None
                if cmd == StatusCodes.GET_LINE:
                    if arg == "cardedit.change_login":
                        self.interactive.writelines(login)
                    else:
                        if success:
                            return self.active
                        else:
                            raise ExecutionError("\n".join(lines))
                elif cmd == StatusCodes.GET_HIDDEN:
                    self.interactive.writelines(admin_pin)
                elif cmd == StatusCodes.SC_OP_SUCCESS:
                    success = True

    def set_language(self, *languages: str, admin_pin: str = "12345678") -> SmartCard:
        """Set language preferences

        Args:
            *languages (str): 1-4 ISO-639 language codes.
            admin_pin (str, optional): Admin PIN. Defaults to "12345678".

        Raises:
            ValueError: If specified arguments are invalid.
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        if len(languages) == 0:
            raise ValueError("At least one language must be specified.")
        if len(languages) > 4:
            raise ValueError("At most 4 languages must be specified.")
        if any([len(i) != 2 for i in languages]):
            raise ValueError(
                "All language entries must be 2-byte ISO-639 language codes."
            )

        self.interactive.writelines("lang")
        success = False
        lines = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status:
                lines.append(line.content)
                cmd = line.code
                arg = line.arguments[0] if len(line.arguments) > 0 else None
                if cmd == StatusCodes.GET_LINE:
                    if arg == "cardedit.change_lang":
                        self.interactive.writelines("".join(languages))
                    else:
                        if success:
                            return self.active
                        else:
                            raise ExecutionError("\n".join(lines))
                elif cmd == StatusCodes.GET_HIDDEN:
                    self.interactive.writelines(admin_pin)
                elif cmd == StatusCodes.SC_OP_SUCCESS:
                    success = True

    def set_salutation(
        self,
        salutation: Literal["male", "female"] | None = None,
        admin_pin: str = "12345678",
    ) -> SmartCard:
        """Sets the cardholder's salutation preferences.

        Args:
            salutation ('male' | 'female' | None, optional): Saltuation mode, or unset if None. Defaults to None.
            admin_pin (str, optional): Admin PIN. Defaults to "12345678".

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated smartcard
        """
        self.interactive.writelines("salutation")
        success = False
        lines = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status:
                lines.append(line.content)
                cmd = line.code
                arg = line.arguments[0] if len(line.arguments) > 0 else None
                if cmd == StatusCodes.GET_LINE:
                    if arg == "cardedit.change_sex":
                        self.interactive.writelines(
                            ("M" if salutation == "male" else "F")
                            if salutation
                            else " "
                        )
                    else:
                        if success:
                            return self.active
                        else:
                            raise ExecutionError("\n".join(lines))
                elif cmd == StatusCodes.GET_HIDDEN:
                    self.interactive.writelines(admin_pin)
                elif cmd == StatusCodes.SC_OP_SUCCESS:
                    success = True

    def set_forced_sig(self, value: bool, admin_pin: str = "12345678") -> SmartCard:
        """Set forced signature mode

        Args:
            value (bool): What value to set to
            admin_pin (str, optional): Admin PIN. Defaults to "12345678".

        Returns:
            SmartCard: Updated smartcard
        """
        current = self.active
        if current.forced_signature_pin == value:
            return current

        self.interactive.writelines("forcesig")
        line = self.interactive.wait_for_status(
            StatusCodes.GET_LINE, StatusCodes.GET_HIDDEN
        )[-1]
        if line.code == StatusCodes.GET_HIDDEN:
            self.interactive.writelines(admin_pin)
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
        return self.active

    def generate_key(
        self,
        real_name: str,
        email: str | None = None,
        comment: str | None = None,
        expires: str | None = None,
        backup: bool = False,
        card_pin: str = "123456",
        admin_pin: str = "12345678",
        key_passphrase: str | None = None,
        force: bool = False,
    ) -> SmartCard:
        """Generates a key on the smartcard, optionally backing up to the local machine.

        Args:
            real_name (str): UID name
            email (str | None, optional): UID email. Defaults to None.
            comment (str | None, optional): UID comment. Defaults to None.
            expires (str | None, optional): Expiration time (None for no expiration, `n` for n days, `nW` for n weeks, etc). Defaults to None.
            backup (bool, optional): Whether to backup to the local machine. Defaults to False.
            card_pin (str, optional): Card PIN. Defaults to "123456".
            admin_pin (str, optional): Card Admin PIN. Defaults to "12345678".
            key_passphrase (str | None, optional): The passphrase for the local backup key. Defaults to None.
            force (bool, optional): Whether to replace existing keys. Defaults to False.

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        self.interactive.writelines("generate")
        success = False
        pinentered = False
        admentered = False
        lines = []
        for line in self.interactive.readlines(yield_empty=False):
            if line.is_status:
                lines.append(line.content)
                cmd = line.code
                arg = line.arguments[0] if len(line.arguments) > 0 else None
                if cmd == StatusCodes.GET_LINE:
                    if arg == "cardedit.genkeys.backup_enc":
                        self.interactive.writelines("y" if backup else "n")
                    elif arg == "keygen.valid":
                        self.interactive.writelines(expires if expires else "0")
                    elif arg == "keygen.name":
                        self.interactive.writelines(real_name)
                    elif arg == "keygen.email":
                        self.interactive.writelines(email if email else "")
                    elif arg == "keygen.comment":
                        self.interactive.writelines(comment if comment else "")
                    elif arg == "cardedit.prompt":
                        if success:
                            return self.active
                        else:
                            raise ExecutionError("\n".join(lines))

                elif cmd == StatusCodes.GET_HIDDEN:
                    if arg == "passphrase.enter":
                        if pinentered:
                            if admentered:
                                if backup:
                                    self.interactive.writelines(
                                        key_passphrase if key_passphrase else ""
                                    )

                            else:
                                self.interactive.writelines(admin_pin)
                                admentered = True
                        else:
                            self.interactive.writelines(card_pin)
                            pinentered = True

                elif (
                    cmd == StatusCodes.GET_BOOL
                    and arg == "cardedit.genkeys.replace_keys"
                ):
                    self.interactive.writelines("y" if force else "n")

                elif cmd == StatusCodes.KEY_CREATED:
                    success = True

    def change_pin(self, current_pin: str, new_pin: str) -> SmartCard:
        """Change the user PIN of the key

        Args:
            current_pin (str): Current user PIN
            new_pin (str): New user PIN

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        self.interactive.writelines("passwd")
        line = self.interactive.wait_for_status(StatusCodes.GET_LINE)[-1]
        if line.arguments[0] == "cardutil.change_pin.menu":
            self.interactive.writelines("1", current_pin, new_pin, new_pin)
        else:
            raise ExecutionError("Failed to change PIN")

        line = self.interactive.wait_for_status(
            StatusCodes.SC_OP_SUCCESS, StatusCodes.SC_OP_FAILURE
        )[-1]
        self.interactive.wait_for_status(StatusCodes.GET_LINE)
        if line.code == StatusCodes.SC_OP_SUCCESS:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            return self.active
        else:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            raise ExecutionError("Failed to change PIN")

    def unblock_pin_as_admin(self, admin_pin: str, new_pin: str) -> SmartCard:
        """Unblock a user PIN with the admin PIN

        Args:
            admin_pin (str): Admin PIN
            new_pin (str): New user PIN

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        self.interactive.writelines("passwd")
        line = self.interactive.wait_for_status(StatusCodes.GET_LINE)[-1]
        if line.arguments[0] == "cardutil.change_pin.menu":
            self.interactive.writelines("2", admin_pin, new_pin, new_pin)
        else:
            raise ExecutionError("Failed to unblock PIN")

        line = self.interactive.wait_for_status(
            StatusCodes.SC_OP_SUCCESS, StatusCodes.SC_OP_FAILURE
        )[-1]
        self.interactive.wait_for_status(StatusCodes.GET_LINE)
        if line.code == StatusCodes.SC_OP_SUCCESS:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            return self.active
        else:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            raise ExecutionError("Failed to unblock PIN")

    def unblock_pin(self, reset_code: str, new_pin: str) -> SmartCard:
        """Unblock the user PIN with a reset code.

        Args:
            reset_code (str): Reset code
            new_pin (str): New user PIN

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        self.interactive.writelines("unblock")
        line = self.interactive.wait_for_status(
            StatusCodes.GET_LINE, StatusCodes.GET_HIDDEN
        )[-1]
        if line.code == StatusCodes.GET_LINE:
            raise ExecutionError("Reset code is unavailable or otherwise inaccessible.")

        self.interactive.writelines(reset_code, new_pin, new_pin)
        line = self.interactive.wait_for_status(
            StatusCodes.SC_OP_SUCCESS, StatusCodes.SC_OP_FAILURE
        )[-1]
        self.interactive.wait_for_status(StatusCodes.GET_LINE)
        if line.code == StatusCodes.SC_OP_SUCCESS:
            return self.active
        else:
            raise ExecutionError("Failed to unblock PIN")

    def change_admin_pin(self, current_pin: str, new_pin: str) -> SmartCard:
        """Change the admin PIN

        Args:
            current_pin (str): Current admin PIN
            new_pin (str): New admin PIN

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        self.interactive.writelines("passwd")
        line = self.interactive.wait_for_status(StatusCodes.GET_LINE)[-1]
        if line.arguments[0] == "cardutil.change_pin.menu":
            self.interactive.writelines("3", current_pin, new_pin, new_pin)
        else:
            raise ExecutionError("Failed to change Admin PIN")

        line = self.interactive.wait_for_status(
            StatusCodes.SC_OP_SUCCESS, StatusCodes.SC_OP_FAILURE
        )[-1]
        self.interactive.wait_for_status(StatusCodes.GET_LINE)
        if line.code == StatusCodes.SC_OP_SUCCESS:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            return self.active
        else:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            raise ExecutionError("Failed to change Admin PIN")

    def change_reset_code(self, admin_pin: str, reset_code: str) -> SmartCard:
        """Changes the card's reset code

        Args:
            admin_pin (str): Admin PIN
            reset_code (str): New reset code

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        self.interactive.writelines("passwd")
        line = self.interactive.wait_for_status(StatusCodes.GET_LINE)[-1]
        if line.arguments[0] == "cardutil.change_pin.menu":
            self.interactive.writelines("4", admin_pin, reset_code, reset_code)
        else:
            raise ExecutionError("Failed to change reset code")

        line = self.interactive.wait_for_status(
            StatusCodes.SC_OP_SUCCESS, StatusCodes.SC_OP_FAILURE
        )[-1]
        self.interactive.wait_for_status(StatusCodes.GET_LINE)
        if line.code == StatusCodes.SC_OP_SUCCESS:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            return self.active
        else:
            self.interactive.writelines("Q")
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            raise ExecutionError("Failed to change reset code")

    def set_usage_info(
        self, type: Literal["sign", "decrypt", "auth"], value: bool, admin_pin: str
    ) -> SmartCard:
        """Sets card UIF data

        Args:
            type (sign | decrypt | auth): Which UIF flag to set
            value (bool): What value to set it to
            admin_pin (str): Card admin PIN

        Raises:
            ExecutionError: If operation fails

        Returns:
            SmartCard: Updated card
        """
        indexMap = {"sign": 1, "decrypt": 2, "auth": 3}
        self.interactive.writelines(f"uif {indexMap[type]} {'on' if value else 'off'}")
        line = self.interactive.wait_for_status(
            StatusCodes.GET_LINE, StatusCodes.GET_HIDDEN
        )[-1]
        if line.code == StatusCodes.GET_LINE:
            raise ExecutionError("Input is invalid.")

        self.interactive.writelines(admin_pin)
        line = self.interactive.wait_for_status(
            StatusCodes.GET_LINE, StatusCodes.SC_OP_FAILURE
        )[-1]
        if line.code == StatusCodes.GET_LINE:
            return self.active
        else:
            self.interactive.wait_for_status(StatusCodes.GET_LINE)
            raise ExecutionError("Incorrect PIN")
