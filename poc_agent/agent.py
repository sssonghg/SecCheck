from langchain_ollama import ChatOllama
from urllib.parse import unquote

from .schemas import Finding, PoCRequest
from .prompts import poc_prompt

class PoCAgent:
    def __init__(self, model: str = "qwen2.5:7b"):
        self.llm = ChatOllama(
            model=model,
            temperature=0
        )

        self.structured_llm = self.llm.with_structured_output(
            PoCRequest,
            method="json_schema"
        )

        self.chain = poc_prompt | self.structured_llm

    def validate_request(
        self,
        finding: Finding,
        result: PoCRequest
    ) -> None:

        endpoint = finding.endpoint

        if endpoint.httpMethods:
            if result.method not in endpoint.httpMethods:
                raise ValueError(
                    f"Invalid HTTP method: {result.method}"
                )

        matched = False
        path_params = {}

        if (
            not result.endpoint.startswith("/")
            or result.endpoint.startswith("//")
            or any(c in result.endpoint for c in ("?", "#", "\\"))
        ):
            raise ValueError("Invalid endpoint format")

        actual_parts = result.endpoint.split("/")

        for path in endpoint.paths:
            expected_parts = path.split("/")

            if len(expected_parts) != len(actual_parts):
                continue

            valid = True
            values = {}

            for expected, actual in zip(expected_parts, actual_parts):

                if expected.startswith("{") and expected.endswith("}"):
                    name = expected[1:-1]
                    value = unquote(actual)

                    if not value or "/" in value or "\\" in value:
                        valid = False
                        break

                    if value in (".", ".."):
                        valid = False
                        break

                    values[name] = value

                elif expected != actual:
                    valid = False
                    break

            if valid:
                matched = True
                path_params = values
                break

        if not matched:
            raise ValueError(
                f"Invalid endpoint: {result.endpoint}"
            )

        for param in endpoint.params:

            if param.in_ == "query" and param.required:
                if result.queryParams.get(param.name) is None:
                    raise ValueError(
                        f"Missing query parameter: {param.name}"
                    )

            elif param.in_ == "path" and param.required:
                if param.name not in path_params:
                    raise ValueError(
                        f"Missing path parameter: {param.name}"
                    )

            elif param.in_ == "body":
                if param.required and result.body is None:
                    raise ValueError("Missing request body")

                if param.fields and result.body is not None:
                    if not isinstance(result.body, dict):
                        raise ValueError("Invalid DTO body format")

                    allowed_fields = {
                        field.name for field in param.fields
                    }

                    for key in result.body:
                        if key not in allowed_fields:
                            raise ValueError(
                                f"Invalid body field: {key}"
                            )

        if endpoint.consumes and result.body is not None:
            headers = {
                key.lower(): value
                for key, value in result.headers.items()
            }

            content_type = headers.get(
                "content-type", ""
            ).split(";")[0].strip().lower()

            allowed_types = [
                value.lower()
                for value in endpoint.consumes
            ]

            if content_type not in allowed_types:
                raise ValueError(
                    f"Invalid Content-Type: {content_type}"
                )

    def generate(self, finding: Finding) -> PoCRequest:
        result = self.chain.invoke({
            "vuln_instruction": (
                "Generate a benign baseline HTTP test request."
            ),
            "finding": finding.model_dump_json(
                by_alias=True,
                indent=2
            )
        })

        result.findingId = finding.findingId
        result.vulnType = finding.vulnType

        self.validate_request(finding, result)

        return result