import pytest

from urlthreat.normalize import normalize_path, normalize_url


def test_scheme_host_case_and_trailing_dot():
    u = normalize_url("HTTPS://X.EXAMPLE.TEST.:443/a")
    assert (u.scheme, u.host, u.port) == ("https", "x.example.test", 443)


def test_default_ports():
    assert normalize_url("http://a.test/").port == 80
    assert normalize_url("https://a.test/").port == 443
    assert normalize_url("http://a.test:8080/").port == 8080


def test_empty_path_is_root():
    assert normalize_url("https://a.test").segments == ("", "")
    assert normalize_url("https://a.test/").segments == ("", "")


def test_userinfo_query_fragment_ignored():
    u = normalize_url("https://user:pw@a.test/p?q=/x#frag")
    assert u.host == "a.test"
    assert u.segments == ("", "p")


def test_percent_decodes_unreserved_only():
    assert normalize_path("/%62%2f%7e") == ("", "b%2F~")


def test_percent_hex_uppercased_no_double_decode():
    assert normalize_path("/%25%36%32") == ("", "%2562")


def test_encoded_slash_not_separator():
    assert normalize_path("/a%2Fb") == ("", "a%2Fb")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/a/./b", ("", "a", "b")),
        ("/a/../b", ("", "b")),
        ("/../a", ("", "a")),
        ("/a/../../b", ("", "b")),
        ("/a//b", ("", "a", "", "b")),
        ("/a/.", ("", "a", "")),
        ("/a/..", ("", "")),
        ("/a/b/..", ("", "a", "")),
    ],
)
def test_dot_segments(raw, expected):
    assert normalize_path(raw) == expected


def test_unsupported_scheme_rejected():
    with pytest.raises(ValueError):
        normalize_url("ftp://a.test/")
