import setuptools


def get_readme():
    with open('README.md', 'r') as fh:
        long_description = fh.read()
    return long_description


def get_requirements():
    lines = [line.strip() for line in open('requirements.txt', 'r')]
    return [line for line in lines if line and not line.startswith('#')]


import importlib
if importlib.util.find_spec('apsw') is None:
    from subprocess import check_call,CalledProcessError
    def install_apsw(method='pip',version='3.31.1',tag='-r1'):
        if method == 'pip':
            version = '3.31.1'
            tag = '-r1'
            print('Installing apsw...')
            check_call(f'''\
                pip install  \
                https://github.com/rogerbinns/apsw/releases/download/{version}{tag}/apsw-{version}{tag}.zip \
                --global-option=fetch \
                --global-option=--version \
                --global-option={version} \
                --global-option=--all \
                --global-option=build  \
                --global-option=--enable=rtree \
            '''.split())
        else:
            raise ValueError(f'{method} not supported to install apsw')
    install_apsw()


setuptools.setup(
    name='clquery',
    version='0.0.1rc2',
    author='Dongting Yu',
    author_email='dongtingyu@gmail.com',
    description='SQL interface to your cloud resources',
    long_description=get_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/dongting/clquery',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=get_requirements(),
    entry_points={
        'console_scripts': [
            'clquery = clquery.shell:interactive_mode'
        ]
    },
)
