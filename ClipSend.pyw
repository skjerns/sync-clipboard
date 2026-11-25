"""Windows: double-click to start ClipSend without a console window.

Needs Python 3 from python.org and:  py -m pip install --user PySide6 requests cryptography keyring truststore
"""
import os
import runpy
import sys

script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipsend.py')
sys.argv = [script] + sys.argv[1:]
runpy.run_path(script, run_name='__main__')
