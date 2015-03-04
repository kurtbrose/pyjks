from distutils.core import setup
import os


readme_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'README.md')
with open(readme_path) as f:
    long_description = f.read()

setup(
    name='pyjks',
    version='0.3',
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
