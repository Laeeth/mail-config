#!/usr/bin/env python2
import sys
import argparse
from offlineimap import get_keepass


def get_pass(args):
    if not args.method:
        args.method = 'pass'
    print(get_keepass(args.method,
                      group_name=args.group_name, title=args.title))


def main(args=None):
    parser = argparse.ArgumentParser(prog=__file__)
    parser.add_argument('-g', '--group_name',
                        help='Group name of entry')
    parser.add_argument('-t', '--title',
                        help='Title of entry')
    parser.add_argument('-m', '--method',
                        help='Method that get info of entry: '
                        'user(Username), pass(Password),'
                        'client_id(Client ID), client_secret(Client Secret)'
                        'refresh_token(Refresh Token)'
                        'app_pass(Application Password)')
    parser.set_defaults(run=get_pass)
    args = parser.parse_args(args=args)
    args.run(args)

sys.exit(main())
