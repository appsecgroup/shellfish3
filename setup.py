from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='shellfish3',
    version='1.1',
    author='AppSecGroup',
    description='Custom fork of the requests library for extended API calls',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/appsecgroup/shellfish3',
    license='MIT',
    include_package_data=True,
    packages=find_packages(include=[
        "shellfish3", "shellfish3.*"
    ]),
    package_data={
        '': ['*']
    },
    install_requires=[
        "charset_normalizer>=2,<4",
        "idna>=2.5,<4",
        "urllib3>=1.21.1,<3",
        "certifi>=2017.4.17",
    ],
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3 :: Only",
    ]
)
