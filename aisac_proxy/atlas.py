"""Maps internal rule IDs to MITRE ATLAS technique IDs and names.
Source: https://atlas.mitre.org/techniques.

This is a curated subset, not the full taxonomy. Add entries as new rules
are introduced. Keeping this table separate from rules.py makes it cheap
to display the mapping in the README and in the alert output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AtlasEntry:
    id: str
    name: str


ATLAS_BY_RULE: dict[str, AtlasEntry] = {
    "R-DESC-01": AtlasEntry("AML.T0051.000", "LLM Prompt Injection: Direct"),
    "R-DESC-02": AtlasEntry("AML.T0051.000", "LLM Prompt Injection: Direct"),
    "R-DESC-03": AtlasEntry("AML.T0053", "LLM Plugin Compromise"),
    "R-TOOL-04": AtlasEntry("AML.T0053", "LLM Plugin Compromise"),
    "R-CALL-05": AtlasEntry("AML.T0053", "LLM Plugin Compromise"),
    "R-CALL-06": AtlasEntry("AML.T0057", "LLM Data Leakage"),
    "R-CALL-07": AtlasEntry("AML.T0057", "LLM Data Leakage"),
}
