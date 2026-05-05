"""
============================================
BLACK WALL — Abstract Repository (DAO Base)
============================================
Defines the interface that any database backend must implement.
To add MySQL support, create a MySQLRepository(AlertRepository)
— zero changes to services or controllers needed.
"""

from abc import ABC, abstractmethod


class AlertRepository(ABC):
    """Abstract Data Access Object for alert storage."""

    @abstractmethod
    def init_db(self) -> None:
        """Initialize database tables/schema."""
        ...

    @abstractmethod
    def save_detections(self, detections: list[dict]) -> int:
        """
        Persist a list of detection dictionaries.
        Returns the number of records saved.
        """
        ...

    @abstractmethod
    def get_alert_history(self, limit: int = 100) -> list[dict]:
        """Retrieve the most recent alerts."""
        ...

    @abstractmethod
    def get_stats(self) -> dict:
        """Return aggregated statistics."""
        ...
