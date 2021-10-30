from sm4 import key_schedule, sm4
import pytest


@pytest.fixture
def m():
    return bytes.fromhex('0123456789abcdeffedcba9876543210')


@pytest.fixture
def c():
    return bytes.fromhex('681edf34d206965e86b3e94f536e4246')


@pytest.fixture
def rk(m):
    return key_schedule(m)


def test_ks(m, rk):
    correct_rk = [0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
                  0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
                  0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
                  0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
                  0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
                  0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
                  0xb79bd80c, 0x1d2115b0, 0xe228aeb, 0xf1780c81,
                  0x428d3654, 0x62293496, 0x1cf72e5, 0x9124a012]
    rk = key_schedule(m)
    assert all([a == b for a, b in zip(rk, correct_rk)])


def test_sm4_encrypt(m, c, rk):
    assert sm4(m, rk) == c


def test_sm4_decrypt(m, c, rk):
    assert sm4(c, rk[::-1]) == m
