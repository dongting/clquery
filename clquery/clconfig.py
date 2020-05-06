import argparse
import pkg_resources
import apsw


class ClqueryConfig(object):
    args = None

    @classmethod
    def parse_args(cls, argv):
        parser = argparse.ArgumentParser(
            description='clquery command line tool.'
        )
        parser.add_argument(
            '--aws-profile',
            default=None,
            required=False,
            help='AWS profile name of the credentials to use.'
        )
        parser.add_argument(
            '-V',
            '--version',
            action='version',
            version=', '.join([
                'clquery ' + pkg_resources.require('clquery')[0].version,
                'apsw ' + apsw.apswversion(),
                'sqlite ' + apsw.sqlitelibversion()
            ])
        )
        args = parser.parse_args()
        cls.set_all(args)

    @classmethod
    def set_all(cls, args):
        cls.args = args

    @classmethod
    def get(cls, arg):
        return getattr(cls.args, arg, None)
