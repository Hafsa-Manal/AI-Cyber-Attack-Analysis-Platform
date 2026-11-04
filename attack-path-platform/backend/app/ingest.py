"""ingest.py - read nodes.csv and edges.csv and check that they are correct.

SAFETY: this file only READS files. It never connects to any network.

How to use it:
    nodes, edges = load_network("nodes.csv", "edges.csv")
The two inputs can be file paths or open files (like an upload from FastAPI).
If something is wrong, it raises IngestError with a clear message.
"""
import re

import pandas as pd

# The columns each file must have
NODE_COLUMNS = ["id", "name", "type", "software", "version", "is_entry_point", "is_sensitive"]
EDGE_COLUMNS = ["source", "target", "connection", "port"]

# The only connection types we accept
CONNECTION_TYPES = ["network_access", "shared_login", "db_access"]


class IngestError(ValueError):
    """A problem with an input file. The message is safe to show to the user."""


def _read_csv(source, label):
    """Read a CSV into a table (DataFrame) where every value is text."""
    try:
        # dtype=str keeps "2016" as text. keep_default_na=False keeps blanks as "".
        # utf-8-sig removes the hidden marker that Excel adds to CSV files.
        table = pd.read_csv(source, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    except pd.errors.EmptyDataError:
        raise IngestError(f"{label} is empty. It needs a header row and at least one data row.")
    except (pd.errors.ParserError, UnicodeDecodeError):
        raise IngestError(f"{label} could not be read. Please check that it is a valid CSV file.")

    # Remove extra spaces around the column names and the values
    table.columns = [str(c).strip() for c in table.columns]
    table = table.apply(lambda column: column.str.strip())

    if len(table) == 0:
        raise IngestError(f"{label} has a header row but no data rows.")
    return table


def _check_columns(table, required, label):
    """Make sure every required column is there."""
    missing = [c for c in required if c not in table.columns]
    if missing:
        raise IngestError(
            f"{label} is missing column(s): {', '.join(missing)}. "
            f"Expected columns: {', '.join(required)}."
        )


def _line(index):
    """Table row 0 is line 2 in the file (line 1 is the header)."""
    return index + 2


def _to_int_column(table, column, label):
    """Turn a text column into whole numbers. Stop at the first bad value."""
    numbers = []
    for index, value in table[column].items():
        if not re.fullmatch(r"\d+", value):
            raise IngestError(
                f"{label} line {_line(index)}: {column} '{value}' must be a whole number."
            )
        numbers.append(int(value))
    return numbers


def _to_bool_column(table, column, label):
    """Turn yes/no text into True/False."""
    result = []
    for index, value in table[column].items():
        answer = value.lower()
        if answer not in ("yes", "no"):
            raise IngestError(
                f"{label} line {_line(index)}: {column} must be 'yes' or 'no', not '{value}'."
            )
        result.append(answer == "yes")
    return result


def load_nodes(source, label="nodes.csv"):
    """Read and check nodes.csv. Returns a clean table."""
    table = _read_csv(source, label)
    _check_columns(table, NODE_COLUMNS, label)
    table = table[NODE_COLUMNS].copy()  # keep only the columns we know

    table["id"] = _to_int_column(table, "id", label)
    table["is_entry_point"] = _to_bool_column(table, "is_entry_point", label)
    table["is_sensitive"] = _to_bool_column(table, "is_sensitive", label)

    # name and type must not be blank. software and version may be blank.
    for column in ["name", "type"]:
        for index, value in table[column].items():
            if value == "":
                raise IngestError(f"{label} line {_line(index)}: {column} must not be blank.")

    # every id must be used only once
    seen = {}
    for index, node_id in table["id"].items():
        if node_id in seen:
            raise IngestError(
                f"{label} line {_line(index)}: id {node_id} is already used on line {seen[node_id]}."
            )
        seen[node_id] = _line(index)

    return table.reset_index(drop=True)


def load_edges(source, node_ids, label="edges.csv"):
    """Read and check edges.csv. node_ids is the set of ids from nodes.csv."""
    table = _read_csv(source, label)
    _check_columns(table, EDGE_COLUMNS, label)
    table = table[EDGE_COLUMNS].copy()

    table["source"] = _to_int_column(table, "source", label)
    table["target"] = _to_int_column(table, "target", label)
    table["port"] = _to_int_column(table, "port", label)

    for index, row in table.iterrows():
        line = _line(index)
        # both ends of the connection must be machines from nodes.csv
        for end in ["source", "target"]:
            if row[end] not in node_ids:
                raise IngestError(f"{label} line {line}: {end} {row[end]} is not an id in nodes.csv.")
        if row["source"] == row["target"]:
            raise IngestError(f"{label} line {line}: a machine cannot connect to itself.")
        if row["connection"] not in CONNECTION_TYPES:
            raise IngestError(
                f"{label} line {line}: connection '{row['connection']}' is not allowed. "
                f"Use one of: {', '.join(CONNECTION_TYPES)}."
            )
        if not 1 <= row["port"] <= 65535:
            raise IngestError(f"{label} line {line}: port {row['port']} must be between 1 and 65535.")

    return table.reset_index(drop=True)


def load_network(nodes_source, edges_source):
    """Read both files. Returns (nodes_table, edges_table)."""
    nodes = load_nodes(nodes_source)
    edges = load_edges(edges_source, set(nodes["id"]))
    return nodes, edges
