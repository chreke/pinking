import argparse
import logging
from functools import partial
from proxy import ipfs_proxy_handler, run_proxy


async def _proxy_handler(request, target_url):
    """
    Intercept calls to ipfs and add auth header
    """
    return await ipfs_proxy_handler(request, target_url)


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
    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(format='%(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=args.loglvl,
                        filename=args.logfile)

    run_proxy(partial(_proxy_handler, target_url=args.target_url), args.listen_port)
