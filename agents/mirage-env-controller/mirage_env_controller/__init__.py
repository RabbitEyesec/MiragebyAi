"""MirageEnvironmentController — the restricted sandbox-mutation service
(Appendix G, Step 9b).

`__build_hash__` is a placeholder overwritten at install-package build time
(mirroring installers/endpoint/build.ps1's pattern for MirageEndpoint) so a
running agent's build_hash always matches what Step 3's allowlist expects.
"""

__build_hash__ = "0" * 64
