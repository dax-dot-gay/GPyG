from pydantic import BaseModel


class UserID(BaseModel):
    name: str | None = None
    email: str
    comment: str | None = None

    def __str__(self):
        if not self.name and not self.comment:
            return self.email
        else:
            return f"{self.name + ' ' if self.name else ''}{f'({self.comment}) ' if self.comment else ''}<{self.email}>"
