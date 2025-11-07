class ApiError(Exception):
    """
    Generic API exception
    """

    pass


class ApiConfigurationError(ApiError):
    """
    Configuration error in either the API or the settings.
    """

    pass


class ApiTemporaryError(ApiError):
    """
    Likely temporary error in the API.
    """

    pass
