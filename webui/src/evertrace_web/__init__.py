"""Independent, on-demand Web presentation; no eager framework imports."""


class BackendError(Exception):
    def __init__(self, code="backend_unavailable"):
        self.code = code
        super().__init__(code)
