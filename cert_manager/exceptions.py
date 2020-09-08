class CertManagerException(Exception):
    def __init__(self, description, error=None, url=None):
        self.description = description
        self.code = error
        self.url = url

    def __str__(self):
        print('dafuq')
        print(self.description)
        print(self.code)
        print(self.url)
        if self.url and self.error:
          print("A")
          return(repr(f"({self.code}) {self.description} from: {self.url}"))
        elif self.url and not self.error:
          print("B")
          return(repr(f"{self.description} from: {self.url}"))
        elif not self.url and self.error:
          print("C")
          return(repr(f"({self.code}) {self.description}"))
        else:
          print("D")
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
