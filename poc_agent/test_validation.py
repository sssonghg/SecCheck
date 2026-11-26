from .schemas import Finding, PoCRequest
from .agent import PoCAgent


def main():
    agent = PoCAgent()

    finding = Finding.model_validate({
        "findingId": "TEST-001",
        "vulnType": "SQL_INJECTION",
        "endpoint": {
            "httpMethods": ["POST"],
            "paths": ["/api/test/{id}"],
            "consumes": ["application/json"],
            "params": [
                {
                    "name": "id",
                    "in": "path",
                    "javaType": "String",
                    "required": True,
                    "tainted": False
                },
                {
                    "name": "request",
                    "in": "body",
                    "javaType": "TestRequest",
                    "required": True,
                    "tainted": False,
                    "fields": [
                        {
                            "name": "username",
                            "javaType": "String",
                            "tainted": False
                        }
                    ]
                }
            ]
        },
        "location": {
            "file": "TestController.java",
            "className": "TestController",
            "method": "test",
            "startLine": 10,
            "endLine": 20
        },
        "sink": {
            "call": "test",
            "line": 15,
            "code": ""
        },
        "taintPath": [],
        "methodSource": ""
    })

    request = PoCRequest(
        findingId="TEST-001",
        vulnType="SQL_INJECTION",
        method="POST",
        endpoint="/api/test/123",
        headers={"Content-Type": "application/json"},
        queryParams={},
        body={"username": "testuser"}
    )

    agent.validate_request(finding, request)

    print("Validation PASS")

    # 잘못된 HTTP Method
    invalid_request = request.model_copy(
        update={"method": "GET"}
    )

    try:
        agent.validate_request(finding, invalid_request)
        print("FAIL: Invalid method accepted")
    except ValueError as e:
        print(f"PASS: {e}")

    # Body 누락
    invalid_request = request.model_copy(
        update={"body": None}
    )

    try:
        agent.validate_request(finding, invalid_request)
        print("FAIL: Missing body accepted")
    except ValueError as e:
        print(f"PASS: {e}")

    # 잘못된 Content-Type
    invalid_request = request.model_copy(
        update={"headers": {"Content-Type": "text/plain"}}
    )

    try:
        agent.validate_request(finding, invalid_request)
        print("FAIL: Invalid Content-Type accepted")
    except ValueError as e:
        print(f"PASS: {e}")

if __name__ == "__main__":
    main()