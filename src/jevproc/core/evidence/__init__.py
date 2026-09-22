"""Read-only OS evidence backends. No inference, rendering, or mutable target state."""


class CollectionError(RuntimeError):
    pass
