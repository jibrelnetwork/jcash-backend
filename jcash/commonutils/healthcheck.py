import datetime
import os
import platform
from pathlib import Path


def get_version_information():
    version = 'n/a'
    version_file = Path(os.path.dirname(os.path.dirname(__file__))).parent / 'version.txt'

    if version_file.exists() and version_file.is_file():
        version = version_file.read_text().strip()

    return version


def get_sys_uptime():
    try:
        return str(datetime.timedelta(seconds=float(Path('/proc/uptime').read_text().split()[0])))
    except Exception:
        return 'n/a'


def get_app_uptime():
    return str(datetime.datetime.now() - start_time)


def get_load_avg():
    try:
        return os.getloadavg()
    except OSError:
        return 'n/a'


def healthcheck():
    data = {
        'hostname': hostname,
        'version': version,

        'loadavg': get_load_avg(),
        'uptime': get_app_uptime(),
        'sys_uptime': get_sys_uptime(),
    }

    return data


hostname = platform.node()
start_time = datetime.datetime.now()
version = get_version_information()
