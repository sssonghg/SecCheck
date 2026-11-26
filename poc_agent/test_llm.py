from langchain_ollama import ChatOllama
from pydantic import BaseModel

class HTTPRequest(BaseModel):
    method: str
    endpoint: str

llm = ChatOllama(
    model="qwen2.5:7b",
    temperature=0
)

structured_llm = llm.with_structured_output(
    HTTPRequest,
    method="json_schema"
)

response = structured_llm.invoke(
    "Generate a GET request to the /test endpoint."
)

print(response)
print(type(response))
print(response.model_dump_json(indent=2))