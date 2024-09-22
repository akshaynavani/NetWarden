"""Host inventory with an explicit allowlist.

Every component that wants to reach out to the network goes through :class:`Inventory`. If a
target is not declared in the config, :class:`TargetNotAllowed` is raised -- there is no code
path that probes arbitrary addresses.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from netwarden.config import Host, NetWardenConfig


class TargetNotAllowed(Exception):
    """Raised when something tries to act on a host that is not in the inventory."""


class Inventory:
    def __init__(self, config: NetWardenConfig) -> None:
        self._config = config
        self._by_name: dict[str, Host] = {h.name: h for h in config.hosts}
        self._addresses: set[str] = {h.address.lower() for h in config.hosts}

    def __iter__(self) -> Iterator[Host]:
        return iter(self._by_name.values())

    def __len__(self) -> int:
        return len(self._by_name)

    @property
    def config(self) -> NetWardenConfig:
        return self._config

    def get(self, name: str) -> Host:
        try:
            return self._by_name[name]
        except KeyError:
            raise TargetNotAllowed(f"host {name!r} is not in the configured inventory") from None

    def require_address(self, address: str) -> None:
        if address.lower() not in self._addresses:
            raise TargetNotAllowed(f"address {address!r} is not in the configured inventory")

    def select(
        self, names: Iterable[str] | None = None, tags: Iterable[str] | None = None
    ) -> list[Host]:
        """Return hosts filtered by explicit names and/or tags (intersection)."""
        hosts = list(self._by_name.values())
        if names:
            wanted = list(names)
            hosts = [self.get(n) for n in wanted]
        if tags:
            tagset = set(tags)
            hosts = [h for h in hosts if tagset & set(h.tags)]
        return hosts
