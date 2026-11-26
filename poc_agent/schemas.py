from pydantic import BaseModel, Field
from typing import Literal, Any

class BodyField(BaseModel):
    name: str
    javaType: str
    tainted: bool

class Parameter(BaseModel):
    name: str
    in_: Literal[
        "query", "path", "body", "header", "cookie"
    ] = Field(alias="in")
    javaType: str
    required: bool
    defaultValue: str | None = None
    tainted: bool
    fields: list[BodyField] = Field(default_factory=list)

class Endpoint(BaseModel):
    httpMethods: list[str]
    paths: list[str]
    consumes: list[str]
    params: list[Parameter]

class Location(BaseModel):
    file: str
    className: str
    method: str
    startLine: int
    endLine: int

class Sink(BaseModel):
    call: str
    line: int
    code: str

class TaintPath(BaseModel):
    var: str
    line: int
    kind: str

class Finding(BaseModel):
    findingId: str
    vulnType: Literal[
        "COMMAND_INJECTION",
        "SPEL_INJECTION",
        "SQL_INJECTION"
    ]
    endpoint: Endpoint
    location: Location
    sink: Sink
    taintPath: list[TaintPath]
    methodSource: str

class AnalyzerResult(BaseModel):
    schemaVersion: str
    project: str
    findings: list[Finding]

class PoCRequest(BaseModel):
    findingId: str
    vulnType: Literal[
        "COMMAND_INJECTION",
        "SPEL_INJECTION",
        "SQL_INJECTION"
    ]
    method: Literal[
        "GET", "POST", "PUT",
        "DELETE", "PATCH", "HEAD", "OPTIONS"
    ]
    endpoint: str
    headers: dict[str, str] = Field(default_factory=dict)
    queryParams: dict[str, Any] = Field(default_factory=dict)
    body: Any = None