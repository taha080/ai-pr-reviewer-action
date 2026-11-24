"""Deliberately sloppy class design — exercises CLS101–CLS105.

Used to dogfood the Python class-design rules on a real PR.
Do not copy this style.
"""


class Config:
    """Application settings, held as plain attributes."""

    host: str = "localhost"
    port: int = 8080


class Base:
    """Base class with a real initialiser."""

    def __init__(self, name: str) -> None:
        """Store the name."""
        self.name = name


class Child(Base):
    """Child that adds nothing to its parent's initialiser."""

    def __init__(self, name: str) -> None:
        """Pass everything straight through to Base."""
        super().__init__(name)


class Helper:
    """Helper whose method never touches the instance."""

    def greet(self) -> str:
        """Return a greeting."""
        return "hello"


class Point:
    """A point that defines equality but no hash."""

    def __init__(self, x: int, y: int) -> None:
        """Store the coordinates."""
        self.x = x
        self.y = y

    def __eq__(self, other: object) -> bool:
        """Compare coordinates."""
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y


class Placeholder:
    """A class left empty."""

    pass


class Widget:
    """A well-behaved class, for contrast."""

    def __init__(self, label: str) -> None:
        """Store the label."""
        self.label = label

    def describe(self) -> str:
        """Describe the widget."""
        return f"Widget: {self.label}"

    def __eq__(self, other: object) -> bool:
        """Compare labels."""
        if not isinstance(other, Widget):
            return NotImplemented
        return self.label == other.label

    def __hash__(self) -> int:
        """Hash the label."""
        return hash(self.label)
