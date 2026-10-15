"""Names that could carry markup are refused where they enter."""
import pytest

from labels import check_label


@pytest.mark.parametrize("ok", ["kyc-service", "marketing-mac-1", "order service", "app.log:prod", "payments/api v2", "नाम", "a_b+c(1)"])
def test_ordinary_names_pass(ok):
    assert check_label(ok, "x") == ok


@pytest.mark.parametrize("bad", [
    "<img src=x onerror=alert(1)>", "a<b", "x>y", 'say "hi"', "it's", "a&b", "`cmd`", "line\nbreak", "tab\there", "nul\x00", "del\x7f",
])
def test_names_that_could_carry_markup_are_refused(bad):
    with pytest.raises(ValueError):
        check_label(bad, "source_system")
