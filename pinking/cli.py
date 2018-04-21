import os
import sys
import logging
import argparse
from .proxies.local_proxy import main as daemon_main
from .proxies.server_proxy import main as server_main


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'manage':
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pinking.pinking.settings")
        try:
            from django.core.management import execute_from_command_line
        except ImportError as exc:
            raise ImportError(
                "Couldn't import Django. Are you sure it's installed and "
                "available on your PYTHONPATH environment variable? Did you "
                "forget to activate a virtual environment?"
            ) from exc
        execute_from_command_line([sys.argv[0]] + sys.argv[2:])
        return

    desc = 'pinking cli utility'
    lvl_map = {
        'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING,
        'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL
    }
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--listen_port", help="set the listening port",
                        type=int, default=5001)
    parser.add_argument("--target_url", help="set the target url (daemon only)",
                        type=str, default="https://pinking.io")
    parser.add_argument("-u", "--username", help="Username (daemon only)")
    parser.add_argument("-p", "--password", help="Password (daemon only)")
    parser.add_argument("--ipfs_port", help="set the ipfs port (server only)",
                        type=int, default=5001)
    parser.add_argument("--django_port", help="set the django port (server only)",
                        type=int, default=8000)
    parser.add_argument("--ssl_cert_path", help="use ssl certs at path (server only)", type=str)
    parser.add_argument("--logfile", help="the optional output log file", type=str)
    parser.add_argument("--loglvl", help="the log level",
                        type=str, choices=list(lvl_map.keys()), default='INFO')
    parser.add_argument('run', type=str, help='type of proxy or django', choices=['server', 'daemon', 'manage'])
    args = parser.parse_args()

    if args.run == 'server':
        server_main(args)
    elif args.run == 'daemon':
        daemon_main(args)


if __name__ == '__main__':
    main()
