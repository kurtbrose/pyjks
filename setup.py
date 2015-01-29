from distutils.core import setup


with open('README.md') as f:
    long_description = f.read()

setup(
    name='pyjks',
    version='0.1.1',
    author="Kurt Rose",
    author_email="kurt@kurtrose.com",
    description='pure python jks file parser',
    license="MIT",
    url="http://github.com/doublereedkurt/pyjks",
    long_description=long_description,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
    ],
    packages=['jks'],
    install_requires=['pyasn1'],
)
