"""Method metadata shared by providers and discovery; no registry imports."""
from dataclasses import dataclass

@dataclass(frozen=True)
class MethodSpec:
    id: str
    input_type: str
    output_type: str
    source: str
    operation: str = ""
    unavailable_reason: str = "no_verified_lookup"
    baseline: bool = True

    @property
    def implemented(self) -> bool:
        return bool(self.operation)

    @property
    def description(self) -> str:
        return f"Retrieve {self.output_type} related to {self.input_type} using {self.source} ({self.operation or self.unavailable_reason})."

def supported_method(source: str, input_type: str, output_type: str,
                     operation: str, *, baseline: bool = True) -> MethodSpec:
    """Declare a provider capability whose retrieval and parser are implemented."""
    return MethodSpec(id=f"{source}.{input_type}_to_{output_type}",
                      input_type=input_type, output_type=output_type, source=source,
                      operation=operation, unavailable_reason="", baseline=baseline)
