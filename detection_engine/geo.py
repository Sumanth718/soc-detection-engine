"""Offline IP geolocation used by the impossible-travel detection.

The built-in table only covers the IP ranges reserved for documentation
(RFC 5737) that appear in the sample logs. For real data, export a GeoIP
database (for example MaxMind GeoLite2) to CSV and load it with
``GeoResolver.from_csv``.
"""

from __future__ import annotations

import csv
import ipaddress
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Location:
    country: str
    city: str
    lat: float
    lon: float

    def __str__(self) -> str:
        return f"{self.city}, {self.country}"


# CIDR -> location. Documentation ranges only, so no real host is implied.
_DEFAULT_TABLE: dict[str, Location] = {
    "192.0.2.0/25": Location("FR", "Paris", 48.8566, 2.3522),
    "192.0.2.128/25": Location("IN", "Hyderabad", 17.3850, 78.4867),
    "198.51.100.0/25": Location("SG", "Singapore", 1.3521, 103.8198),
    "198.51.100.128/25": Location("US", "Ashburn", 39.0438, -77.4874),
    "203.0.113.0/25": Location("RU", "Moscow", 55.7558, 37.6173),
    "203.0.113.128/25": Location("BR", "Sao Paulo", -23.5505, -46.6333),
}


class GeoResolver:
    def __init__(self, table: dict[str, Location] | None = None) -> None:
        source = table if table is not None else _DEFAULT_TABLE
        self._networks = [(ipaddress.ip_network(cidr), loc) for cidr, loc in source.items()]

    @classmethod
    def from_csv(cls, path: str | Path) -> GeoResolver:
        """Load a CSV with columns ``network,country,city,lat,lon``."""
        table: dict[str, Location] = {}
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                table[row["network"]] = Location(
                    row["country"], row["city"], float(row["lat"]), float(row["lon"])
                )
        return cls(table)

    def lookup(self, ip: str | None) -> Location | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None  # e.g. CloudTrail "signin.amazonaws.com"
        for network, location in self._networks:
            if addr.version == network.version and addr in network:
                return location
        return None


def haversine_km(a: Location, b: Location) -> float:
    """Great-circle distance between two locations in kilometres."""
    r = 6371.0
    phi1, phi2 = math.radians(a.lat), math.radians(b.lat)
    dphi = math.radians(b.lat - a.lat)
    dlmb = math.radians(b.lon - a.lon)
    h = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))
