import shlex
from pathlib import Path

import pytest

from tg_candidate_runner import (
    _build_mini_extra_cmd,
    _combine_filter,
    _models_for_candidates,
)


def test_models_for_candidates_single_repeats() -> None:
    assert _models_for_candidates(3, "m1") == ["m1", "m1", "m1"]


def test_models_for_candidates_exact() -> None:
    assert _models_for_candidates(2, "a,b") == ["a", "b"]


def test_models_for_candidates_invalid_length() -> None:
    with pytest.raises(ValueError):
        _models_for_candidates(3, "a,b")


def test_combine_filter_instances_and_filter() -> None:
    combined = _combine_filter("id1,id2", "foo")
    assert combined == "(foo)|(id1|id2)"


def test_combine_filter_instances_only() -> None:
    combined = _combine_filter("alpha,beta", None)
    assert combined == "alpha|beta"


def test_build_mini_extra_cmd() -> None:
    base_cmd = shlex.split("mini-extra swebench")
    cmd = _build_mini_extra_cmd(
        base_cmd,
        subset="lite",
        split="test",
        output_dir=Path("out"),
        workers=1,
        model="demo",
        limit=2,
        filter_text="foo|bar",
        extra_args=["--foo", "bar"],
    )

    assert cmd[:2] == base_cmd
    assert "--output" in cmd
    assert "--model" in cmd
    assert "--filter" in cmd
    assert cmd[-2:] == ["--foo", "bar"]
