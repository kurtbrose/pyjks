from distutils.core import setup

setup(
    name='pyjks',
    version='0.1',
    author="Kurt Rose",
    author_email="kurt@kurtrose.com",
    description='pure python jks file parser',
    license="MIT",
    url="http://github.com/doublereedkurt/pyjks",
    long_description=open('README.md').read(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
    ],
    packages=['jks'],
    requires=['pyasn1'],)
