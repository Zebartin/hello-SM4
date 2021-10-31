import multiprocessing
from functools import partial
from typing import Callable, List

import click

SM4_SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
    0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
    0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
    0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
    0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
    0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
    0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
    0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
    0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
    0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
    0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
]
SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
]


def bytes2int(x: bytes) -> int:
    """bytes转int，方便进行异或等运算"""
    return int.from_bytes(x, 'big')


def int2bytes(x: int, n: int = 4) -> bytes:
    """将x取模避免溢出，然后转化为字节表示"""
    # 这里n表示字节数，左移3位后表示比特数
    return (x % (1 << (n << 3))).to_bytes(n, 'big')


def rtol(x: int, n: int, m: int = 32) -> int:
    """m位内的循环左移"""
    return ((x << n) & 0xFFFFFFFF) | ((x >> (m-n)) & 0xFFFFFFFF)


def lowest_byte(x: int) -> int:
    return x & 0xFF


def func_L(t: int) -> int:
    return t ^ rtol(t, 2) ^ rtol(t, 10) ^ rtol(t, 18) ^ rtol(t, 24)


def func_L_prime(x: int) -> int:
    return x ^ rtol(x, 13) ^ rtol(x, 23)


def func_S(x: int) -> int:
    """将32位整数放入S盒处理"""
    t = 0
    t |= SM4_SBOX[lowest_byte(x >> 24)] << 24
    t |= SM4_SBOX[lowest_byte(x >> 16)] << 16
    t |= SM4_SBOX[lowest_byte(x >> 8)] << 8
    t |= SM4_SBOX[lowest_byte(x)]
    return t


def func_T(x: int) -> int:
    return func_L(func_S(x))


def func_T_prime(x: int) -> int:
    return func_L_prime(func_S(x))


def key_schedule(key: bytes) -> List[int]:
    """SM4的密钥扩展算法"""
    mk = [bytes2int(key[4*i:4*(i+1)]) for i in range(4)]
    rk = [a ^ b for a, b in zip(mk, SM4_FK)]
    for i in range(32):
        rk.append(rk[i] ^ func_T_prime(
            rk[i+1] ^ rk[i+2] ^ rk[i+3] ^ SM4_CK[i]))
    return rk[4:]


def sm4(m: bytes, rk: List[int]) -> bytes:
    """SM4密码算法"""
    X = [bytes2int(m[4*i:4*(i+1)]) for i in range(4)]
    for i in range(32):
        X.append(X[i] ^ func_T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]))
    # 取X的最后4个，并逆序拼接起来
    return b''.join([int2bytes(x) for x in X[:-5:-1]])


def padding(m: bytes) -> bytes:
    """ECB的padding"""
    l = 16 - len(m) % 16
    return m + b''.join([int2bytes(l, 1) for _ in range(l)])


def unpadding(m: bytes) -> bytes:
    """ECB去除padding"""
    return m[:-m[-1]]


def sm4_ecb_(m: bytes, rk: List[int]) -> bytes:
    """ECB核心流程，不包括padding"""
    sm4p = partial(sm4, rk=rk)
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as p:
        return b''.join(p.map(sm4p, [m[16*i:16*(i+1)]
                        for i in range(len(m) // 16)]))


def sm4_ctr_round(m_round: bytes, rk: List[int], iv_round: bytes) -> bytes:
    """CTR每轮对block的计算"""
    l = len(m_round)
    t = sm4(int2bytes(iv_round, 16), rk)[:l]
    return int2bytes(bytes2int(m_round) ^ bytes2int(t), l)


def sm4_ctr_(m: bytes, rk: List[int], iv: int) -> bytes:
    """CTR核心流程"""
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as p:
        return b''.join(p.starmap(sm4_ctr_round,
                        [(m[16*i:16*(i+1)], rk, iv+i) for i in range(len(m) // 16)]))


def fix_hex_str(x: str, func: Callable) -> str:
    """对用户输入的hex字符串进行处理"""
    if len(x) < 32:
        click.echo('hex string is too short, padding with zero bytes to length')
        x += ''.join(['0']*(32-len(x)))
    elif len(x) > 32:
        click.echo('hex string is too long, ignoring excess')
        x = x[:32]
    try:
        return func(x)
    except ValueError:
        click.echo('non-hex digit')
        raise click.UsageError('invalid hex key value')


def fix_key(key: str) -> bytes:
    return fix_hex_str(key, lambda x: bytes.fromhex(x))


def fix_iv(iv: str) -> int:
    return fix_hex_str(iv, lambda x: int(x, 16))


@click.group()
def cli():
    pass


@cli.command()
@click.option('-e/-d', 'encrypt', required=True, default=None, help='Encrypt/decrypt')
@click.option('-in', 'in_file', required=True, type=click.File(mode='rb'), help='Input file')
@click.option('-out', 'out_file', required=True, type=click.File(mode='wb'), help='Output file')
@click.option('-K', 'key', required=True, type=str, help='Raw key, in hex')
def sm4_ecb(encrypt, key, in_file, out_file):
    in_bytes = in_file.read()
    rk = key_schedule(fix_key(key))
    if encrypt:
        res = sm4_ecb_(padding(in_bytes), rk)
    else:
        res = unpadding(sm4_ecb_(in_bytes, rk[::-1]))
    out_file.write(res)


@cli.command()
@click.option('-e/-d', 'encrypt', required=True, default=None, help='Encrypt/decrypt')
@click.option('-in', 'in_file', required=True, type=click.File(mode='rb'), help='Input file')
@click.option('-out', 'out_file', required=True, type=click.File(mode='wb'), help='Output file')
@click.option('-K', 'key', required=True, type=str, help='Raw key, in hex')
@click.option('-iv', required=True, type=str, help='IV in hex')
def sm4_ctr(encrypt, key, iv, in_file, out_file):
    out_file.write(sm4_ctr_(
        in_file.read(),
        key_schedule(fix_key(key)),
        fix_iv(iv)
    ))
