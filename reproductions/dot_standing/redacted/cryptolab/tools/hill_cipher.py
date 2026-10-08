""

from __future__ import annotations

from typing import Literal

from cryptolab.tools.alphabets import STD_ALPHABET, keyed_alphabet

MOD = 26
TransformMode = Literal["encode", "decode"]

type Matrix = list[list[int]]


def _valuation(alphabet_keyword: str | None) -> tuple[str, dict[str, int]]:
    alphabet = keyed_alphabet(alphabet_keyword) if alphabet_keyword else STD_ALPHABET
    return alphabet, {symbol: position for position, symbol in enumerate(alphabet)}


def hill_matrix_from_keyword(keyword: str, size: int, valuation_keyword: str | None) -> Matrix:
    ""

    if size < 2:
        raise ValueError(f"hill: size must be >= 2, got {size}")
    _, index = _valuation(valuation_keyword)
    values = [index[symbol] for symbol in keyword.upper() if symbol in index]
    if len(values) != size * size:
        raise ValueError(
            f"hill: keyword must supply exactly {size * size} alphabet letters for size {size}, "
            f"got {len(values)}"
        )
    return [values[row * size:(row + 1) * size] for row in range(size)]


def _mat_inverse_prime(matrix: Matrix, prime: int) -> Matrix | None:
    ""

    size = len(matrix)
    work: list[list[int]] = [
        [value % prime for value in matrix[row]] + [1 if col == row else 0 for col in range(size)]
        for row in range(size)
    ]
    for col in range(size):
        pivot = next((row for row in range(col, size) if work[row][col] % prime != 0), -1)
        if pivot == -1:
            return None
        work[col], work[pivot] = work[pivot], work[col]
        inv = pow(work[col][col] % prime, -1, prime)
        work[col] = [(value * inv) % prime for value in work[col]]
        for row in range(size):
            if row == col:
                continue
            factor = work[row][col] % prime
            if factor:
                work[row] = [
                    (cell - factor * pivot_cell) % prime
                    for cell, pivot_cell in zip(work[row], work[col], strict=True)
                ]
    return [row[size:] for row in work]


def _mat_inverse_mod(matrix: Matrix) -> Matrix | None:
    ""

    inverse_2 = _mat_inverse_prime(matrix, 2)
    inverse_13 = _mat_inverse_prime(matrix, 13)
    if inverse_2 is None or inverse_13 is None:
        return None

    return [
        [(13 * inverse_2[row][col] + 14 * inverse_13[row][col]) % MOD for col in range(len(matrix))]
        for row in range(len(matrix))
    ]


def matrix_is_invertible(matrix: Matrix) -> bool:
    ""

    return _mat_inverse_mod(matrix) is not None


def _mat_vec(matrix: Matrix, vector: list[int]) -> list[int]:
    return [sum(matrix[i][k] * vector[k] for k in range(len(vector))) % MOD for i in range(len(matrix))]


def hill_transform(
    text: str,
    *,
    mode: TransformMode,
    keyword: str,
    size: int = 3,
    alphabet_keyword: str | None = "KRYPTOS",
    valuation_keyword: str | None = None,
) -> tuple[str, tuple[str, ...]]:
    ""

    if mode not in {"encode", "decode"}:
        raise ValueError(f"hill: unsupported mode {mode!r}")
    valuation = valuation_keyword if valuation_keyword is not None else alphabet_keyword
    matrix = hill_matrix_from_keyword(keyword, size, valuation)
    inverse = _mat_inverse_mod(matrix)
    if inverse is None:
        raise ValueError("hill: key matrix is not invertible mod 26")
    if mode == "decode":
        matrix = inverse
    alphabet, index = _valuation(alphabet_keyword)
    if len(text) % size != 0:
        raise ValueError(f"hill: text length {len(text)} is not a multiple of block size {size}")
    values = [index[symbol] for symbol in text if symbol in index]
    if len(values) != len(text):
        raise ValueError("hill: text contains symbols outside the alphabet")
    out: list[str] = []
    for start in range(0, len(values), size):
        block = _mat_vec(matrix, values[start:start + size])
        out.extend(alphabet[value] for value in block)
    return "".join(out), ()
