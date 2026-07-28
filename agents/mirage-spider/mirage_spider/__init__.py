"""MirageSpider — the read-only sandbox sensing service (Appendix G).

`__build_hash__` is a placeholder overwritten at MSI build time (mirroring
installers/endpoint/build.ps1's pattern for MirageEndpoint) so a running
agent's build_hash always matches what Step 3's allowlist expects.
"""

__build_hash__ = "0" * 64
