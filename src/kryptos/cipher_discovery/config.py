"""Configuration for cipher discovery subsystem."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DiscoveryConfig:
    """All configurable parameters for the discovery pipeline."""

    # Database
    db_path: str = "db/cipher_discovery.sqlite"

    # Fetching
    max_concurrent_fetches: int = 4
    default_politeness_delay: float = 2.0  # seconds between requests to same domain
    per_domain_delays: dict = field(default_factory=lambda: {
        "en.wikipedia.org": 1.0,
        "www.cipherhistory.com": 3.0,
    })
    user_agent: str = "KryptosBot-CipherDiscovery/0.1 (research; +https://internal.com)"
    max_retries: int = 3
    retry_backoff_base: float = 2.0
    request_timeout: float = 30.0
    respect_robots_txt: bool = True

    # Cache
    cache_dir: str = "db/cipher_discovery_cache"
    cache_ttl_hours: int = 168  # 1 week

    # Expansion
    max_expansion_depth: int = 2
    max_queries_per_seed: int = 5
    max_total_frontier_entries: int = 2000

    # Scoring weights (for K4 relevance)
    scoring_weights: dict = field(default_factory=lambda: {
        "manual_executability": 2.0,
        "artist_feasibility": 1.5,
        "spatial_geometric": 1.5,
        "compass_bearing_relation": 2.0,
        "morse_signaling_relation": 1.5,
        "bespoke_hybrid": 1.5,
        "physical_aid_use": 1.0,
        "short_text_plausibility": 1.0,
        "sanborn_theme_compatibility": 1.5,
    })

    # Pipeline
    workers: int = 4  # for fetch/extract parallelism (I/O bound, not CPU)
    batch_size: int = 50
    checkpoint_interval: int = 100  # entries between checkpoints

    # Reporting
    report_dir: str = "reports/cipher_discovery"
    top_n_report: int = 30

    def ensure_dirs(self):
        """Create necessary directories."""
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
        Path(self.report_dir).mkdir(parents=True, exist_ok=True)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
