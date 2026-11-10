"""An authorizer and a mailer held as module-level instances (methods reached via an instance)."""

REAL_CALLS: list[str] = []


class Authz:
    def check(self, who: str, what: str) -> bool:
        return who == "alice"

    @staticmethod
    def static_check(who: str) -> bool:
        return who == "alice"

    @classmethod
    def class_check(cls, who: str) -> bool:
        return who == "alice"

    async def acheck(self, who: str, what: str) -> bool:
        return who == "alice"

    @classmethod
    async def aclass_check(cls, who: str) -> bool:
        return who == "alice"


class Mailer:
    def send(self, n: int) -> str:
        REAL_CALLS.append(f"send {n}")
        return "sent"


authorizer = Authz()
mailer = Mailer()
