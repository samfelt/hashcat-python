import hashcat
import pytest
from contextlib import nullcontext

@pytest.mark.parametrize(
    ("input_attack", "resolved_attack_mode"),
    (
        pytest.param(hashcat.AttackMode.brute_force, hashcat.AttackMode.brute_force, id="resolve enum"),
        pytest.param(3, hashcat.AttackMode.brute_force, id="resolve int"),
    )
)
def test_attack_mode_resolve(input_attack, resolved_attack_mode):
    mode = hashcat.AttackMode.resolve_mode(input_attack)
    assert mode == resolved_attack_mode

@pytest.mark.parametrize(
    ("input_attack", "exception"),
    (
        pytest.param(3, nullcontext(), id="no exception"),
        pytest.param(99, pytest.raises(ValueError), id="bad int"),
        pytest.param("straight", pytest.raises(TypeError), id="bad type"),
    )
)
def test_attack_mode_resolve_exceptions(input_attack, exception):
    with exception:
        mode = hashcat.AttackMode.resolve_mode(input_attack)
        assert mode is not None


@pytest.mark.parametrize(
    ("input_mode", "resolved_hash_mode"),
    (
        pytest.param(hashcat.HashMode.sha1, hashcat.HashMode.sha1, id="resolve enum"),
        pytest.param(100 , hashcat.HashMode.sha1, id="resolve int"),
#        pytest.param(123 , ValueError, id="bad int"),
#        pytest.param("sha1", TypeError, id="bad type"),
    )
)
def test_hash_mode_resolve(input_mode, resolved_hash_mode):
    mode = hashcat.HashMode.resolve_mode(input_mode)
    assert mode == resolved_hash_mode

@pytest.mark.parametrize(
    ("input_mode", "exception"),
    (
        pytest.param(1400, nullcontext(), id="no exception"),
        pytest.param(123, pytest.raises(ValueError), id="bad int"),
        pytest.param("sha1", pytest.raises(TypeError), id="bad type"),
    )
)
def test_hash_mode_resolve_exceptions(input_mode, exception):
    with exception:
        mode = hashcat.HashMode.resolve_mode(input_mode)
        assert mode is not None
