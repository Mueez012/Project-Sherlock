"""Transport-independent workflow outcomes, rendered by CLI and HTTP adapters."""


class WorkflowServiceError(RuntimeError):
    def __init__(self, code, message, status=409, *, details=None, run_id=None, step_id=None):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status
        self.details = details or {}
        self.run_id, self.step_id = run_id, step_id
