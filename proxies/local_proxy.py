import argparse
import logging
import getpass
from aiohttp import web
from aiohttp.helpers import BasicAuth
from functools import partial
from proxy import ipfs_proxy_handler


async def _proxy_handler(request, target_url, auth):
    """
    Intercept calls to ipfs and add auth header
    """
    response, _ = await ipfs_proxy_handler(request, target_url, auth=auth)
    return response


async def _cleanup():
    pass


if __name__ == '__main__':
    lvl_map = {
        'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING,
        'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL
    }
    parser = argparse.ArgumentParser(description='Run the pinking server proxy')
    parser.add_argument("--listen_port", help="set the listening port",
                        type=int, default=5001)
    parser.add_argument("--target_url", help="set the target port",
                        type=str, default="https://pinking.io")
    parser.add_argument("--logfile", help="the optional output log file", type=str)
    parser.add_argument("--loglvl", help="the log level",
                        type=str, choices=list(lvl_map.keys()), default='INFO')
    parser.add_argument("-u", "--username", help="Username", type=str)
    parser.add_argument("-p", "--password", help="Password", type=str)
    args = parser.parse_args()

    username = args.username
    if username is None:
        username = input("Username: ")

    password = args.password
    if password is None:
        password = getpass.getpass()

    # Set up logging
    logging.basicConfig(format='local proxy: %(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=args.loglvl,
                        filename=args.logfile)


    app = web.Application()
    basic_auth = BasicAuth(username, password)
    proxy_handler = partial(_proxy_handler, target_url=args.target_url,
                            auth=basic_auth)
    app.router.add_route('*', '/{path:.*?}', proxy_handler)
    try:
        web.run_app(app, host='0.0.0.0', port=args.listen_port)
    except KeyboardInterrupt:
        asyncio.get_event_loop().run_until_complete(_cleanup())
