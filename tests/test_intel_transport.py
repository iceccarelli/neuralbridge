"""The urllib transport's guards, exercised through an in-memory opener (CONTRACT FIXTURE).

No socket is opened: ``opener`` replaces the network. The redirect handler and URL checks are
the real code.
"""

from __future__ import annotations

import io
import urllib.error
import urllib.request
from email.message import Message

import pytest

from assurance.intel.transport import (
    HostNotAllowed,
    RedirectRefused,
    ResponseTooLarge,
    TransportError,
)
from assurance.intel.transport_urllib import (
    UrllibTransport,
    _SameHostRedirect,
    check_url,
    parse_retry_after,
)

KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def headers(**kw):
    m = Message()
    for k, v in kw.items():
        m[k.replace("_", "-")] = v
    return m


class Resp:
    def __init__(self, body=b"{}", status=200, **hdr):
        self._io = io.BytesIO(body)
        self.status = status
        self.headers = headers(**hdr)

    def read(self, n=-1):
        return self._io.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Opener:
    """Replays a script of responses or exceptions, one per open()."""

    def __init__(self, *script):
        self.script = list(script)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, dict(request.header_items()), timeout))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def http_error(code, body=b"", **hdr):
    return urllib.error.HTTPError(KEV, code, "x", headers(**hdr), io.BytesIO(body))


def transport(opener, **kw):
    sleeps = []
    t = UrllibTransport(opener=opener, sleep=sleeps.append, **kw)
    t.sleeps = sleeps
    return t


# -- host allow-list ----------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "http://www.cisa.gov/x", "https://evil.example/x", "https://www.cisa.gov.evil.example/x",
    "https://cisa.gov/x", "https://user:pw@www.cisa.gov/x", "https://www.cisa.gov:8443/x",
    "ftp://www.cisa.gov/x", "file:///etc/passwd", "https://www.cisa.gov@evil.example/",
    "//www.cisa.gov/x", "https://WWW.CISA.GOV.evil/x",
])
def test_anything_but_an_exact_https_allowed_host_is_refused_before_any_request(url):
    opener = Opener()
    with pytest.raises(HostNotAllowed):
        transport(opener).get(url, {}, 5)
    assert opener.requests == []


def test_the_allowed_hosts_are_exactly_the_three_source_hosts_by_default():
    for host in ("www.cisa.gov", "services.nvd.nist.gov", "api.first.org"):
        assert check_url(f"https://{host}/p", UrllibTransport().allowed_hosts) == host
    with pytest.raises(HostNotAllowed):
        check_url("https://vendor.example/csaf.json", UrllibTransport().allowed_hosts)
    assert check_url("https://vendor.example/csaf.json", ["vendor.example"]) == "vendor.example"


# -- redirects ----------------------------------------------------------------------------
def test_a_redirect_to_another_host_is_refused():
    handler = _SameHostRedirect(frozenset({"www.cisa.gov", "api.first.org"}))
    req = urllib.request.Request(KEV)
    for target in ("https://evil.example/x", "https://api.first.org/x",    # allowed host, but not the same
                   "http://www.cisa.gov/x"):                              # downgrade
        with pytest.raises(RedirectRefused):
            handler.redirect_request(req, None, 302, "Found", headers(), target)


def test_a_same_host_https_redirect_is_followed():
    handler = _SameHostRedirect(frozenset({"www.cisa.gov"}))
    nxt = handler.redirect_request(urllib.request.Request(KEV), io.BytesIO(), 302, "Found",
                                   headers(), "https://www.cisa.gov/other.json")
    assert nxt.full_url == "https://www.cisa.gov/other.json"


def test_an_unfollowed_3xx_surfacing_as_an_error_is_a_refusal_not_a_status():
    t = transport(Opener(http_error(302)))
    with pytest.raises(RedirectRefused):
        t.get(KEV, {}, 5)


def test_a_refusal_raised_inside_the_opener_propagates_unretried():
    opener = Opener(urllib.error.URLError(RedirectRefused("elsewhere")), Resp())
    with pytest.raises(RedirectRefused):
        transport(opener).get(KEV, {}, 5)
    assert len(opener.requests) == 1


# -- size cap -----------------------------------------------------------------------------
def test_the_body_is_cut_off_at_the_cap():
    t = transport(Opener(Resp(b"x" * 100)), max_bytes=50)
    with pytest.raises(ResponseTooLarge) as exc:
        t.get(KEV, {}, 5)
    assert exc.value.status == 200 and len(exc.value.partial) == 51      # one past the cap


def test_a_declared_length_over_the_cap_is_refused_without_reading():
    t = transport(Opener(Resp(b"x", Content_Length="999999")), max_bytes=50)
    with pytest.raises(ResponseTooLarge) as exc:
        t.get(KEV, {}, 5)
    assert exc.value.partial == b""


def test_a_body_exactly_at_the_cap_is_accepted():
    assert transport(Opener(Resp(b"x" * 50)), max_bytes=50).get(KEV, {}, 5) == (200, b"x" * 50)


# -- retry --------------------------------------------------------------------------------
def test_429_and_5xx_are_retried_with_exponential_backoff_then_succeed():
    opener = Opener(http_error(503), http_error(429), Resp(b"ok"))
    t = transport(opener, backoff=2.0)
    assert t.get(KEV, {}, 5) == (200, b"ok")
    assert t.sleeps == [2.0, 4.0] and len(opener.requests) == 3


def test_retry_after_seconds_is_honoured_over_the_backoff():
    t = transport(Opener(http_error(429, Retry_After="7"), Resp(b"ok")), backoff=1.0)
    assert t.get(KEV, {}, 5) == (200, b"ok")
    assert t.sleeps == [7.0]


def test_retry_after_http_date_is_honoured():
    assert parse_retry_after("Fri, 31 Oct 2026 12:00:30 GMT",
                             now=lambda: 1793448000.0) == pytest.approx(30.0)
    assert parse_retry_after("garbage") is None and parse_retry_after(None) is None
    assert parse_retry_after("0") == 0.0


def test_a_retry_after_longer_than_we_will_wait_returns_the_response_unretried():
    opener = Opener(http_error(429, b"slow down", Retry_After="3600"), Resp(b"never"))
    t = transport(opener, max_wait=60.0)
    assert t.get(KEV, {}, 5) == (429, b"slow down")
    assert t.sleeps == [] and len(opener.requests) == 1


def test_retries_are_bounded_and_the_last_status_is_returned_for_recording():
    opener = Opener(*[http_error(503, b"busy") for _ in range(10)])
    t = transport(opener, retries=2)
    assert t.get(KEV, {}, 5) == (503, b"busy")
    assert len(opener.requests) == 3


def test_a_404_is_returned_not_retried():
    opener = Opener(http_error(404, b"nope"), Resp())
    assert transport(opener).get(KEV, {}, 5) == (404, b"nope")
    assert len(opener.requests) == 1


def test_connection_failures_are_retried_then_raised_without_leaking_headers():
    opener = Opener(*[urllib.error.URLError(TimeoutError("t")) for _ in range(3)])
    t = transport(opener, retries=2)
    with pytest.raises(TransportError) as exc:
        t.get(KEV, {"apiKey": "SECRET-VALUE"}, 5)
    assert "SECRET-VALUE" not in str(exc.value) and "3 attempts" in str(exc.value)
    assert len(opener.requests) == 3


def test_the_request_carries_the_header_but_no_compression_and_the_timeout():
    opener = Opener(Resp(b"ok"))
    transport(opener).get(KEV, {"apiKey": "k"}, 12.5)
    url, sent, timeout = opener.requests[0]
    assert sent["Apikey"] == "k" and sent["Accept-encoding"] == "identity" and timeout == 12.5


def test_repr_names_hosts_only():
    assert "apiKey" not in repr(UrllibTransport()) and "www.cisa.gov" in repr(UrllibTransport())
