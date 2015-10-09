import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "vnf manager simulator",
    version = "1.0",
    author = "Manuel Buil, Brady A. Johnson",
    author_email = "manuel.buil@ericsson.com, brady...",
    description = ("A script which simulates an orchestrator"),
    license = "?",
    keywords = "example documentation tutorial",
    url = "https://gerrit.opnfv.org/gerrit/#/c/1587/",
    packages = [".."],
    scripts = [".."],
    long_description=read('README'),
)
