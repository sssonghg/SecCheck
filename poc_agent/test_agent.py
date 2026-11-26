import sys
from pathlib import Path

from .schemas import AnalyzerResult
from .agent import PoCAgent


def main():
    file_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "sample_finding.json"
    )

    json_data = Path(file_path).read_text(
        encoding="utf-8"
    )

    analyzer_result = AnalyzerResult.model_validate_json(
        json_data
    )

    agent = PoCAgent()

    print(f"Project: {analyzer_result.project}")
    print(f"Findings: {len(analyzer_result.findings)}")

    expected_values = {
        "F-001": ("host", "localhost"),
        "F-002": ("expr", "1+1"),
        "F-003": ("name", "testuser")
    }

    for finding in analyzer_result.findings:
        print(f"\nTesting: {finding.vulnType}")

        result = agent.generate(finding)

        print(result.model_dump_json(indent=2))

        if file_path == "sample_finding.json":
            name, expected = expected_values[finding.findingId]

            assert result.queryParams.get(name) == expected, (
                f"Unexpected baseline value: {name}"
            )

        print("Agent Test PASS")


if __name__ == "__main__":
    main()