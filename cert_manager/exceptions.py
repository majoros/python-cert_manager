class CertManagerException(Exception):
    def __init__(self, description, error=None, url=None):
        self.description = description
        self.error = error
        self.url = url

    def __str__(self):
        if self.url and self.error:
          return(repr(f"({self.error}) {self.description} from: {self.url}"))
        elif self.url and not self.error:
          return(repr(f"{self.description} from: {self.url}"))
        elif not self.url and self.error:
          return(repr(f"({self.error}) {self.description}"))
        else:
          return(repr(f"{self.description}"))


class MissingRequiredParam(CertManagerException):
    pass

class BadRequest(CertManagerException):
    pass

class InvalidResponse(CertManagerException):
    pass

class ResponseError(CertManagerException):
    pass

class InvalidRequest(CertManagerException):
    pass
