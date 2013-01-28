from distutils.core import setup, Extension

module1 = Extension('get_ns_list', sources = ['ns_resolve.c'])

setup(name = 'Nameserver Resolve',
      version = '1.0',
      description = 'Test',
      ext_modules = [module1])