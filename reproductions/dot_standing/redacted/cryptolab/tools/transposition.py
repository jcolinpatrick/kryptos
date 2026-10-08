""

from __future__ import annotations

from collections.abc import Callable
from math import gcd


def keyword_to_read_order(keyword: str) -> tuple[int, ...]:
    ""

    if not keyword:
        raise ValueError("columnar keyword must be non-empty")
    return tuple(sorted(range(len(keyword)), key=lambda index: (keyword[index], index)))


def columnar_transform(
    text: str,
    *,
    mode: str,
    width: int,
    read_order: tuple[int, ...],
) -> str:
    ""

    _validate_columnar(width, read_order)
    position_map = _columnar_position_map(len(text), width, read_order)
    if mode == "encode":
        output = [""] * len(text)
        for index, symbol in enumerate(text):
            output[position_map[index]] = symbol
        return "".join(output)
    if mode == "decode":
        return "".join(text[position_map[index]] for index in range(len(text)))
    raise ValueError(f"unsupported transform mode: {mode}")


def rail_fence_transform(text: str, *, mode: str, rails: int) -> str:
    ""

    if isinstance(rails, bool) or not isinstance(rails, int) or rails < 1:
        raise ValueError("rail_fence: rails must be an integer >= 1")
    order = _rail_order(len(text), rails)
    if mode == "encode":
        return "".join(text[index] for index in order)
    if mode == "decode":
        output = [""] * len(text)
        for output_index, input_index in enumerate(order):
            output[input_index] = text[output_index]
        return "".join(output)
    raise ValueError(f"unsupported transform mode: {mode}")


def block_reversal_transform(text: str, *, mode: str, block: int) -> str:
    ""

    if mode not in {"encode", "decode"}:
        raise ValueError(f"unsupported transform mode: {mode}")
    if isinstance(block, bool) or not isinstance(block, int) or block < 1:
        raise ValueError("block_reversal: block must be an integer >= 1")
    return "".join(text[index : index + block][::-1] for index in range(0, len(text), block))


ROUTE_TYPES: tuple[str, ...] = (
    "skip",
    "boustrophedon_rows",
    "boustrophedon_cols",
    "spiral",
    "diagonal",
    "diagonal_alt",
)


def route_transform(
    text: str,
    *,
    mode: str,
    route_type: str,
    width: int | None = None,
    start: int = 0,
    step: int = 1,
) -> str:
    ""

    if mode not in {"encode", "decode"}:
        raise ValueError(f"unsupported transform mode: {mode}")
    order = _route_order(len(text), route_type=route_type, width=width, start=start, step=step)
    if mode == "encode":
        return "".join(text[index] for index in order)
    output = [""] * len(text)
    for output_index, input_index in enumerate(order):
        output[input_index] = text[output_index]
    return "".join(output)


def _route_order(
    length: int,
    *,
    route_type: str,
    width: int | None,
    start: int,
    step: int,
) -> tuple[int, ...]:
    ""

    if length == 0:
        return ()
    if route_type == "skip":
        order = _skip_order(length, start=start, step=step)
    elif route_type == "boustrophedon_rows":
        order = _boustrophedon_rows_order(length, _require_width(width))
    elif route_type == "boustrophedon_cols":
        order = _boustrophedon_cols_order(length, _require_width(width))
    elif route_type == "rotate":
        order = _rotate_order(length, _require_width(width))
    elif route_type == "spiral":
        order = _grid_order(length, _require_width(width), _spiral_coords, start)
    elif route_type == "diagonal":
        order = _grid_order(length, _require_width(width), _diagonal_coords, start)
    elif route_type == "diagonal_alt":
        order = _grid_order(length, _require_width(width), _diagonal_alt_coords, start)
    else:
        raise ValueError(f"route: unknown route_type {route_type!r}")


    if len(order) != length or sorted(order) != list(range(length)):
        raise ValueError(f"route: {route_type} did not produce a valid permutation of length {length}")
    return order


def _require_width(width: int | None) -> int:
    if width is None or isinstance(width, bool) or not isinstance(width, int) or width < 1:
        raise ValueError("route: grid routes require an integer width >= 1")
    return width


def _skip_order(length: int, *, start: int, step: int) -> tuple[int, ...]:
    if isinstance(step, bool) or not isinstance(step, int) or step < 1:
        raise ValueError("route skip: step must be an integer >= 1")
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise ValueError("route skip: start must be an integer >= 0")
    if gcd(step, length) != 1:
        raise ValueError(
            f"route skip: step {step} must be coprime with length {length} to form a permutation"
        )
    base = start % length
    return tuple((base + k * step) % length for k in range(length))


def _boustrophedon_rows_order(length: int, width: int) -> tuple[int, ...]:
    rows = (length + width - 1) // width
    order: list[int] = []
    for row in range(rows):
        columns = range(width) if row % 2 == 0 else range(width - 1, -1, -1)
        for column in columns:
            index = row * width + column
            if index < length:
                order.append(index)
    return tuple(order)


def _boustrophedon_cols_order(length: int, width: int) -> tuple[int, ...]:
    rows = (length + width - 1) // width
    order: list[int] = []
    for column in range(width):
        row_range = range(rows) if column % 2 == 0 else range(rows - 1, -1, -1)
        for row in row_range:
            index = row * width + column
            if index < length:
                order.append(index)
    return tuple(order)


def _rotate_order(length: int, width: int) -> tuple[int, ...]:
    ""

    rows = (length + width - 1) // width
    order: list[int] = []
    for column in range(width):
        for row in range(rows - 1, -1, -1):
            index = row * width + column
            if index < length:
                order.append(index)
    return tuple(order)


def _grid_order(
    length: int,
    width: int,
    coords: Callable[[int, int, int], list[tuple[int, int]]],
    start: int,
) -> tuple[int, ...]:
    rows = (length + width - 1) // width
    cells = coords(rows, width, start)
    order: list[int] = []
    for row, column in cells:
        index = row * width + column
        if index < length:
            order.append(index)
    return tuple(order)


def _spiral_coords(rows: int, cols: int, start: int) -> list[tuple[int, int]]:
    ""

    if start not in {0, 1, 2, 3}:
        raise ValueError("route spiral: start (corner) must be 0, 1, 2, or 3")
    directions = ((0, 1), (1, 0), (0, -1), (-1, 0))
    origins = {
        0: (0, 0, 0),
        1: (0, cols - 1, 1),
        2: (rows - 1, cols - 1, 2),
        3: (rows - 1, 0, 3),
    }
    row, column, direction = origins[start]
    visited = [[False] * cols for _ in range(rows)]
    cells: list[tuple[int, int]] = []
    for _ in range(rows * cols):
        cells.append((row, column))
        visited[row][column] = True
        d_row, d_column = directions[direction]
        next_row, next_column = row + d_row, column + d_column
        if not (0 <= next_row < rows and 0 <= next_column < cols and not visited[next_row][next_column]):
            direction = (direction + 1) % 4
            d_row, d_column = directions[direction]
            next_row, next_column = row + d_row, column + d_column
        row, column = next_row, next_column
    return cells


def _diagonal_coords(rows: int, cols: int, start: int) -> list[tuple[int, int]]:
    ""

    if start not in {0, 1}:
        raise ValueError("route diagonal: start (direction) must be 0 or 1")
    cells: list[tuple[int, int]] = []
    for diagonal in range(rows + cols - 1):
        diagonal_cells = [(row, diagonal - row) for row in range(rows) if 0 <= diagonal - row < cols]
        if start == 1:
            diagonal_cells.reverse()
        cells.extend(diagonal_cells)
    return cells


def _diagonal_alt_coords(rows: int, cols: int, start: int) -> list[tuple[int, int]]:
    ""

    if start not in {0, 1}:
        raise ValueError("route diagonal_alt: start (direction) must be 0 or 1")
    cells: list[tuple[int, int]] = []
    for diagonal in range(rows + cols - 1):
        diagonal_cells = [(row, diagonal - row) for row in range(rows) if 0 <= diagonal - row < cols]
        if (diagonal % 2 == 1) ^ (start == 1):
            diagonal_cells.reverse()
        cells.extend(diagonal_cells)
    return cells


def _validate_columnar(width: int, read_order: tuple[int, ...]) -> None:
    if isinstance(width, bool) or not isinstance(width, int) or width < 1:
        raise ValueError("columnar: width must be an integer >= 1")
    if sorted(read_order) != list(range(width)):
        raise ValueError(f"columnar: read_order must be a permutation of range({width})")


def _column_lengths(length: int, width: int) -> list[int]:
    base, remainder = divmod(length, width)
    return [base + (1 if column < remainder else 0) for column in range(width)]


def _columnar_position_map(length: int, width: int, read_order: tuple[int, ...]) -> tuple[int, ...]:
    column_lengths = _column_lengths(length, width)
    offsets = [0] * width
    offset = 0
    for column in read_order:
        offsets[column] = offset
        offset += column_lengths[column]
    forward = [0] * length
    for index in range(length):
        row, column = divmod(index, width)
        forward[index] = offsets[column] + row
    return tuple(forward)


def _rail_of(index: int, rails: int) -> int:
    if rails == 1:
        return 0
    cycle = 2 * (rails - 1)
    position = index % cycle
    return position if position < rails else cycle - position


def _rail_order(length: int, rails: int) -> tuple[int, ...]:
    return tuple(
        index for rail in range(rails) for index in range(length) if _rail_of(index, rails) == rail
    )
