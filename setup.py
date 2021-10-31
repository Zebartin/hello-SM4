from setuptools import setup

setup(
    name='hello-sm4',
    version='1.0.0',
    py_modules=['sm4'],
    install_requires=[
        'Click',
    ],
    entry_points={
        'console_scripts': [
            'hello-sm4 = sm4:cli',
        ],
    },
)