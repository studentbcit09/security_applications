import json
import logging
import pyotp

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class AuthenticationServer:
    """
    Docstring for AuthenticationServer
    """

    def __init__(self):
        pass
    
class AuthenticationClient:
    """
    Docstring for AuthenticationClient
    """

    def __init__(self):
        pass

class AuthenticationError(Exception):
    """
    Docstring for AuthenticationError
    """
    pass
