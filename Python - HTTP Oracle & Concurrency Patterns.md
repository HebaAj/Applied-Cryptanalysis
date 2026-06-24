---
tags: [python, cryptohack]
---

# Python - HTTP Oracle & Concurrency Patterns

Patterns for web-based challenges where the "oracle" is an encrypt/decrypt endpoint over HTTP: connection reuse, parallelizing requests, and handling flaky responses.

---

## requests.Session()

Reuses the underlying TCP connection across many requests instead of reconnecting each time. Always use one for repeated calls to the same host:

```python
session = requests.Session()
r = session.get(url)
```

---

## ThreadPoolExecutor — map vs as_completed

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

# map: preserves input order, simple when you need all results in order
with ThreadPoolExecutor(max_workers=8) as ex:
    results = ex.map(try_byte, range(256))   # results[i] <-> try_byte(i)

# as_completed: yields results as they finish — enables early-exit
with ThreadPoolExecutor(max_workers=8) as ex:
    futures = {ex.submit(try_byte, g): g for g in charset}
    for fut in as_completed(futures):
        if (result := fut.result()) is not None:
            break   # stop as soon as a match is found, don't wait for the rest
```

> `future.cancel()` only cancels tasks that haven't *started* yet — already-running requests still complete in the background. Fine for early-exit (you already have your answer), but the program won't necessarily exit instantly.

---

## threading.local()

Gives each thread its own `requests.Session()`, avoiding shared-connection-pool issues under high concurrency:

```python
_local = threading.local()

def get_session():
    if not hasattr(_local, "session"):
        _local.session = requests.Session()
    return _local.session
```

---

## Generator + next(..., default)

Find the first matching result without scanning everything:

```python
found = next((g for g in results if g is not None), None)
```

Lazily pulls the first non-`None` value, or returns `None` if nothing matches — no `for`/`break`/flag-variable boilerplate.

---

## Retry with Backoff

Flaky network calls (rate limits, dropped connections) shouldn't kill the whole run:

```python
def encrypt(data):
    for attempt in range(5):
        try:
            r = session.get(f"{BASE}/{data.hex()}/", timeout=10)
            r.raise_for_status()
            return bytes.fromhex(r.json()["ciphertext"])
        except Exception:
            if attempt == 4:
                raise
            time.sleep(1.5 * (attempt + 1))   # backoff before retrying
```

> If you get `requests.exceptions.JSONDecodeError` or unexpected 404s, print `r.status_code` and `r.text[:200]` before assuming the cause — could be rate limiting, http vs https, or a URL-construction bug (e.g. an empty path segment producing `//`).

---

**See also:** [Python - Toolkit](./Python%20-%20Toolkit.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
