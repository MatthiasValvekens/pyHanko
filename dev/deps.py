# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
import subprocess
import sys
import warnings
import shutil
import tempfile
import platform
import site


OTHER_PACKAGES = [
]


def run():
    """
    Ensures a recent version of pip is installed, then uses that to install
    required development dependencies. Uses git to checkout other modularcrypto
    repos for more accurate coverage data.
    """

    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    build_root = os.path.abspath(os.path.join(package_root, '..'))
    try:
        tmpdir = None
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            major_minor = '%s.%s' % sys.version_info[0:2]
            tmpdir = tempfile.mkdtemp()
            _pip = _bootstrap_pip(tmpdir)

            print("Using pip to install dependencies")
            _pip(['install', '-q', '--upgrade', '-r', os.path.join(package_root, 'requires', 'ci')])

            if OTHER_PACKAGES:
                print("Checking out modularcrypto packages for coverage")
                for pkg_url in OTHER_PACKAGES:
                    pkg_name = os.path.basename(pkg_url).replace('.git', '')
                    pkg_dir = os.path.join(build_root, pkg_name)
                    if os.path.exists(pkg_dir):
                        print("%s is already present" % pkg_name)
                        continue
                    print("Cloning %s" % pkg_url)
                    _execute(['git', 'clone', pkg_url], build_root)
                print()

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return True

def _download(url, dest):
    """
    Downloads a URL to a directory

    :param url:
        The URL to download

    :param dest:
        The path to the directory to save the file in

    :return:
        The filesystem path to the saved file
    """

    filename = os.path.basename(url)
    dest_path = os.path.join(dest, filename)

    if sys.platform == 'win32':
        system_root = os.environ.get('SystemRoot')
        powershell_exe = os.path.join('system32\\WindowsPowerShell\\v1.0\\powershell.exe')
        code = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;"
        code += "(New-Object Net.WebClient).DownloadFile('%s', '%s');" % (url, dest_path)
        _execute([powershell_exe, '-Command', code], dest)

    else:
        _execute(['curl', '--silent', '--show-error', '-O', url], dest)

    return dest_path


def _execute(params, cwd):
    """
    Executes a subprocess

    :param params:
        A list of the executable and arguments to pass to it

    :param cwd:
        The working directory to execute the command in

    :return:
        A 2-element tuple of (stdout, stderr)
    """

    proc = subprocess.Popen(
        params,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd
    )
    stdout, stderr = proc.communicate()
    code = proc.wait()
    if code != 0:
        e = OSError('subprocess exit code was non-zero')
        e.stdout = stdout
        e.stderr = stderr
        raise e
    return (stdout, stderr)


def _get_pip_main(download_dir):
    """
    Executes get-pip.py in the current Python interpreter

    :param download_dir:
        The directory that contains get-pip.py
    """

    module_info = imp.find_module('get-pip', [download_dir])
    get_pip_module = imp.load_module('_cideps.get-pip', *module_info)

    orig_sys_exit = sys.exit
    orig_sys_argv = sys.argv
    sys.exit = lambda c: None
    sys.argv = ['get-pip.py', '--user', '-q']

    get_pip_module.main()

    sys.exit = orig_sys_exit
    sys.argv = orig_sys_argv

    # Unload pip modules that came from the zip file
    module_names = sorted(sys.modules.keys())
    end_token = os.sep + 'pip.zip'
    mid_token = end_token + os.sep + 'pip'
    for module_name in module_names:
        try:
            module_path = sys.modules[module_name].__file__
            if mid_token in module_path or module_path.endswith(end_token):
                del sys.modules[module_name]
        except AttributeError:
            pass

    if sys.path[0].endswith('pip.zip'):
        sys.path = sys.path[1:]

    if site.USER_SITE not in sys.path:
        sys.path.append(site.USER_SITE)


def _bootstrap_pip(tmpdir):
    """
    Bootstraps the current version of pip for use in the current Python
    interpreter

    :param tmpdir:
        A temporary directory to download get-pip.py and cacert.pem

    :return:
        A function that invokes pip. Accepts one arguments, a list of parameters
        to pass to pip.
    """

    try:
        import pip

        print('Upgrading pip')
        pip.main(['install', '-q', '--upgrade', 'pip'])
        certs_path = None

    except ImportError:
        print("Downloading cacert.pem from curl")
        certs_path = _download('https://curl.haxx.se/ca/cacert.pem', tmpdir)

        print("Downloading get-pip.py")
        if sys.version_info[0:2] == (3, 2):
            path = _download('https://bootstrap.pypa.io/3.2/get-pip.py', tmpdir)
        else:
            path = _download('https://bootstrap.pypa.io/get-pip.py', tmpdir)

        print("Running get-pip.py")
        _get_pip_main(tmpdir)

        import pip

    def _pip(args):
        base_args = ['--disable-pip-version-check']
        if certs_path:
            base_args += ['--cert', certs_path]
        if sys.platform == 'darwin' and sys.version_info[0:2] in [(2, 6), (2, 7)]:
            new_args = []
            for arg in args:
                new_args.append(arg)
                if arg == 'install':
                    new_args.append('--user')
            args = new_args
        pip.main(base_args + args)

    return _pip
