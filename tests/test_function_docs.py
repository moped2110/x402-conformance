from pathlib import Path

from tools.check_function_docs import check_function_docs, missing_function_docstrings


def test_function_doc_checker_reports_sync_async_methods_and_nested_functions(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        '''
def documented():
    """Explain the documented function."""

    def nested():
        pass

class Example:
    async def method(self):
        pass
''',
        encoding="utf-8",
    )

    assert missing_function_docstrings(source) == [(5, "nested"), (9, "method")]
    assert check_function_docs([tmp_path]) == [
        f"{source.as_posix()}:5: nested is missing a docstring",
        f"{source.as_posix()}:9: method is missing a docstring",
    ]
