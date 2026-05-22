"""Standard-library HTTP forward proxy with a configurable User-Agent and rate limit.

The package is split into small, single-responsibility modules:

* :mod:`proxyserver.config`        - file-backed, thread-safe configuration store
* :mod:`proxyserver.rate_limiter`  - token-bucket request throttle
* :mod:`proxyserver.forward_proxy` - the forward proxy HTTP handler
* :mod:`proxyserver.config_api`    - REST API used by the web frontend
* :mod:`proxyserver.__main__`      - wires everything together and runs it
"""
