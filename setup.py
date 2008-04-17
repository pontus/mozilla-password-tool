from distutils.core import setup
from distutils.extension import Extension
from Pyrex.Distutils import build_ext

setup(name = 'Mozilla password tool',
      description = 'A tool for displaying and encrypting/decrypting stored passwords',
      author = 'Pontus Freyhult',
      author_email = 'pont_mozpass@soua.net',
      url = 'http://soua.net/mozpass.tar.gz',
      scripts = ['mozpass'],
      ext_modules = [Extension("nss", ["nss.pyx"], libraries=["nss3"])],
      cmdclass = {'build_ext': build_ext}
)
