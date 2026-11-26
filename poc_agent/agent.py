import json
from urllib.parse import unquote
from http.cookies import SimpleCookie

from langchain_ollama import ChatOllama

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

        # 1. HTTP Method 검증
        if endpoint.httpMethods:
            if result.method not in endpoint.httpMethods:
                raise ValueError(
                    f"Invalid HTTP method: {result.method}"
                )

        # 2. Endpoint 및 Path 검증
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

            for expected, actual in zip(
                expected_parts, actual_parts
            ):
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

        # 3. Header 및 Cookie 파싱
        headers = {
            key.lower(): value
            for key, value in result.headers.items()
        }

        cookies = SimpleCookie()
        cookies.load(headers.get("cookie", ""))

        # 4. 파라미터 검증
        for param in endpoint.params:

            # Query 및 Query DTO 검증
            if param.in_ == "query":

                if param.fields:
                    if param.name in result.queryParams:
                        raise ValueError(
                            f"Query DTO must be flattened: {param.name}"
                        )

                    if param.required:
                        for field in param.fields:
                            if result.queryParams.get(field.name) is None:
                                raise ValueError(
                                    f"Missing query field: {field.name}"
                                )

                elif param.required:
                    if result.queryParams.get(param.name) is None:
                        raise ValueError(
                            f"Missing query parameter: {param.name}"
                        )

            # Path 검증
            elif param.in_ == "path" and param.required:
                if param.name not in path_params:
                    raise ValueError(
                        f"Missing path parameter: {param.name}"
                    )

            # Body 검증
            elif param.in_ == "body":

                if param.required and result.body is None:
                    raise ValueError("Missing request body")

                if result.body is None:
                    continue

                # Body DTO 검증
                if param.fields:
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

                # 문자열 Body 검증
                elif param.javaType in (
                    "String", "java.lang.String"
                ):
                    if not isinstance(result.body, str):
                        raise ValueError(
                            "Request body must be a string"
                        )

            # Header 검증
            elif param.in_ == "header" and param.required:
                if param.name.lower() not in headers:
                    raise ValueError(
                        f"Missing header: {param.name}"
                    )

            # Cookie 검증
            elif param.in_ == "cookie" and param.required:
                if param.name not in cookies:
                    raise ValueError(
                        f"Missing cookie: {param.name}"
                    )

        # 5. Content-Type 검증
        if endpoint.consumes and result.body is not None:
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

        # Body 파라미터가 없는 요청 보정
        if not any(
            param.in_ == "body"
            for param in finding.endpoint.params
        ):
            result.body = None

        # DTO body가 JSON 문자열이면 객체로 변환
        has_body_dto = any(
            param.in_ == "body" and param.fields
            for param in finding.endpoint.params
        )

        if has_body_dto and isinstance(result.body, str):
            try:
                result.body = json.loads(result.body)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"DTO body가 올바른 JSON이 아닙니다: {result.body!r}"
                ) from exc

        # Query DTO를 queryParams 최상위 필드로 변환
        for param in finding.endpoint.params:
            if param.in_ != "query" or not param.fields:
                continue

            if param.name not in result.queryParams:
                continue

            dto = result.queryParams[param.name]

            if isinstance(dto, str):
                try:
                    dto = json.loads(dto)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Query DTO가 올바른 JSON이 아닙니다: {dto!r}"
                    ) from exc

            if not isinstance(dto, dict):
                raise ValueError(
                    f"Query DTO '{param.name}' must be an object: {dto!r}"
                )

            allowed_fields = {field.name for field in param.fields}
            unknown_fields = set(dto) - allowed_fields

            if unknown_fields:
                raise ValueError(
                    f"Unknown query DTO fields: {sorted(unknown_fields)}"
                )

            del result.queryParams[param.name]

            for key, value in dto.items():
                result.queryParams.setdefault(key, value)

        self.validate_request(finding, result)

        return result
