import time
import logging
import logging.config
import logging.handlers
import traceback
import datetime
import random
import string
from functools import wraps
from pathlib import Path

from jcash.settings import LOGGING__ROOT_DIR, LOGGING


class AppController:
    _logger = logging.getLogger(__name__)

    def __init__(self):
        self._isInitialized = False  # type: bool
        self._processingSessionID = None  # type: str
        self._processingSessionStartTime = None  # type: datetime

    def init(self):
        self._generateSessionAttributes()

        self._configureLogging()
        self._logger.info("Logging configured.")
        self._logger.info("Generated session ID: {}".format(self._processingSessionID))
        self._logger.info("App successfully initialized.")
        self._isInitialized = True

    def releaseResources(self):
        # self._logger.info("Start to clean temp resources of the app.")
        pass

    def _generateSessionAttributes(self):
        self._processingSessionID = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))
        self._processingSessionStartTime = time.gmtime()

    def _configureLogging(self):
        loggingSubDir = self.getSessionStartTimeStr() + "_" + self.getSessionID()
        loggingDir = Path(LOGGING__ROOT_DIR) / loggingSubDir
        loggingDir.mkdir(parents=True, exist_ok=True)
        logging.config.dictConfig(LOGGING)

    def getSessionID(self) -> str:
        return self._processingSessionID

    def getSessionStartTime(self) -> datetime:
        return self._processingSessionStartTime

    def getSessionStartTimeStr(self) -> str:
        return time.strftime("%Y-%m-%d_%H-%M-%S", self._processingSessionStartTime)


glob_AppControllerInstance = None  # type: AppController
glob_nesting = 0


def getAppController() -> AppController:
    return glob_AppControllerInstance


class AppControllerFactory:
    _logger = logging.getLogger(__name__)

    def __enter__(self) -> AppController:
        global glob_AppControllerInstance  # type: AppController
        global glob_nesting  # type: int
        if glob_AppControllerInstance is None:
            glob_AppControllerInstance = AppController()
            glob_AppControllerInstance.init()
        glob_nesting += 1
        return glob_AppControllerInstance

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self._logger.error('Execution of the app finished with the exception:\n{}'
                               .format(''.join(traceback.format_exception(exc_type, exc_val, exc_tb))))
        global glob_AppControllerInstance  # type: AppController
        global glob_nesting  # type: int
        if glob_AppControllerInstance is not None and glob_nesting == 1:
            glob_AppControllerInstance.releaseResources()
        glob_nesting -= 1


class AppControllerException(Exception):
    pass


def initialize_app(fn):
    """
    Performs initialization of the app before executing the function
    """

    @wraps(fn)
    def f(*args, **kwargs):
        with AppControllerFactory():
            # DBEngineInitController.establishDBConnection()
            return fn(*args, **kwargs)

    return f
