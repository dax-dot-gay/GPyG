from .common import BaseOperator
from ..models import SmartCard


class CardOperator(BaseOperator):
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
