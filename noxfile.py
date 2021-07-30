import nox


codecheck_files = [
    'adapters/', 'clib/', 'faucet/', 'tests/', 'setup.py', 'noxfile.py'
]

python_versions = ['3.6', '3.7', '3.8', '3.9']


@nox.session(python=python_versions)
def pytype(session):
    session.install('-r', 'codecheck-requirements.txt')
    session.run(
        'pytype',
        '--j 2',
        '--config setup.cfg',
        *codecheck_files
    )


@nox.session
def pylint(session):
    session.install('-r', 'codecheck-requirements.txt')

    min_score = 9.50

    session.run(
        'pylint',
        '--rcfile=.pylintrc',
        '--fail-under=%s' % min_score,
        *codecheck_files
    )


@nox.session
def flake8(session):
    session.install('-r', 'codecheck-requirements.txt')
    session.run(
        'flake8',
        '--config=.codecheck',
        *codecheck_files
    )
