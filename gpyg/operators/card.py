from io import BufferedRandom
from typing import Any
from .common import BaseOperator
from ..models import SmartCard
from ..util import StatusInteractive


class CardOperator(BaseOperator):

    def __init__(
        self, gpg: Any, interactive: StatusInteractive, pin_file: BufferedRandom
    ) -> None:
        super().__init__(gpg)
        self.interactive = interactive
        self.pin_file = pin_file

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

    def reset(self):
        self.interactive.writelines("factory-reset", "y", "yes")
        self.debug()
