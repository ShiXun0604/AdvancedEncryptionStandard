# 有關key的錯誤
class KeyExtractionError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


# 加解密時會遇到的錯誤
class NoKeyError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class EncryptionError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class DecryptionError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


def error_catcher(Error: Exception, error_message: str):
    def decorater(func):
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                return result
            except:
                raise Error(error_message)
        return wrapper
    return decorater