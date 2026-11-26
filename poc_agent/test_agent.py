import sys
import json
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
    results = []

    print(f"Project: {analyzer_result.project}")
    print(f"Findings: {len(analyzer_result.findings)}")

    for finding in analyzer_result.findings:
        print(f"\nTesting: {finding.vulnType}")

        result = agent.generate(finding)

        print(result.model_dump_json(indent=2))

        results.append(result.model_dump(mode="json"))

        print("Agent Test PASS")

    # 결과 저장 폴더 생성
    output_dir = Path("poc_agent/output")
    output_dir.mkdir(parents=True, exist_ok=True)

    # 입력 파일별 결과 저장 경로 지정
    output_path = output_dir / (
        Path(file_path).stem + "-requests.json"
    )

    # 최종 출력 데이터 구성
    output_data = {
        "schemaVersion": analyzer_result.schemaVersion,
        "project": analyzer_result.project,
        "results": results
    }

    # JSON 파일 저장
    output_path.write_text(
        json.dumps(output_data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()