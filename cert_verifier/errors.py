class Error(Exception):
    """Base class for exceptions in this module"""
    pass


class InvalidTransactionError(Error):
    pass


class InvalidConnectorError(Error):
    pass


class InvalidCertificateError(Error):
    pass
