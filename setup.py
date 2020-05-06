import os
import inspect
import warnings
import platform

from setuptools.command.install import install as _install
import setuptools


VERSION = '0.1.0'
APSW_VERSION = '3.31.1-r1'
SQLITE_VERSION = '3.31.1'


class install_apsw(setuptools.Command):
    # This step is necessary because PyPI no longer allows non-PyPI
    # dependencies when installing from PyPI.

    description = f'Install APSW {APSW_VERSION} and SQLite {SQLITE_VERSION}'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # In Windows APSW should be installed manually
        if os.name == 'nt':
            print('To complete the installation you have to install APSW: https://github.com/rogerbinns/apsw/releases')
            return

        try:
            import apsw
            if apsw.apswversion() == APSW_VERSION:
                print('APSW %s already installed' % apsw.apswversion())
                return
            else:
                print('APSW %s already installed, need %s' % (
                    apsw.apswversion(), APSW_VERSION)
                )
        except Exception:
            pass

        from subprocess import check_call
        print('Installing APSW...')
        check_call(f'''\
            pip install \
            https://github.com/rogerbinns/apsw/releases/download/{APSW_VERSION}/apsw-{APSW_VERSION}.zip \
            --global-option=fetch \
            --global-option=--version \
            --global-option={SQLITE_VERSION} \
            --global-option=--all \
            --global-option=build  \
            --global-option=--enable-all-extensions \
        '''.split())


class install(_install):
    user_options = _install.user_options
    boolean_options = _install.boolean_options

    def initialize_options(self):
        _install.initialize_options(self)

    @staticmethod
    def _called_from_setup(run_frame):
        """
        Attempt to detect whether run() was called from setup() or by another
        command.  If called by setup(), the parent caller will be the
        'run_command' method in 'distutils.dist', and *its* caller will be
        the 'run_commands' method.  If called any other way, the
        immediate caller *might* be 'run_command', but it won't have been
        called by 'run_commands'. Return True in that case or if a call stack
        is unavailable. Return False otherwise.
        """
        if run_frame is None:
            msg = 'Call stack not available. bdist_* commands may fail.'
            warnings.warn(msg)
            if platform.python_implementation() == 'IronPython':
                msg = 'For best results, pass -X:Frames to enable call stack.'
                warnings.warn(msg)
            return True
        res = inspect.getouterframes(run_frame)[2]
        caller, = res[:1]
        info = inspect.getframeinfo(caller)
        caller_module = caller.f_globals.get('__name__', '')
        return (
            caller_module == 'distutils.dist'
            and info.function == 'run_commands'
        )

    def run(self):
        # Explicit request for old-style install?  Just do it
        if self.old_and_unmanageable or self.single_version_externally_managed:
            _install.run(self)
            self.execute(post_install, (self,), msg='Running post install tasks')
            return

        if not self._called_from_setup(inspect.currentframe()):
            # Run in backward-compatibility mode to support bdist_* commands.
            _install.run(self)
        else:
            self.do_egg_install()
        self.execute(post_install, (self,), msg='Running post install tasks')


def post_install(cmd):
    cmd.run_command('install_apsw')


def get_readme():
    with open('README.md', 'r') as fh:
        long_description = fh.read()
    return long_description


def get_requirements():
    lines = [line.strip() for line in open('requirements.txt', 'r')]
    return [line for line in lines if line and not line.startswith('#')]


setuptools.setup(
    name='clquery',
    version=VERSION,
    author='Dongting Yu',
    author_email='dongtingyu@gmail.com',
    description='SQL interface to your cloud resources',
    long_description=get_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/dongting/clquery',
    project_urls={
        'Source': 'https://github.com/dongting/clquery',
    },
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=get_requirements(),
    cmdclass={
        'install': install,
        'install_apsw': install_apsw
    },
    entry_points={
        'console_scripts': [
            'clquery = clquery.shell:interactive_mode'
        ]
    },
)
