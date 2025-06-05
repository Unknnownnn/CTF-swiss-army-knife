import numpy
import sys
import types

# Fix for numpy docstring issue
def _fix_docstring(obj):
    if isinstance(obj.__doc__, bytes):
        obj.__doc__ = obj.__doc__.decode('utf-8')
    if isinstance(obj.__doc__, str):
        return
    obj.__doc__ = str(obj.__doc__) if obj.__doc__ is not None else ''

# Patch numpy's add_docstring
if hasattr(numpy.core, '_add_docstring'):
    _fix_docstring(numpy.core._add_docstring)
    
# Patch any other potential docstring issues
for name, module in sys.modules.items():
    if isinstance(module, types.ModuleType) and name.startswith('numpy'):
        for obj_name in dir(module):
            try:
                obj = getattr(module, obj_name)
                if hasattr(obj, '__doc__'):
                    _fix_docstring(obj)
            except:
                continue 