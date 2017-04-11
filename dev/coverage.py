# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import coverage
import imp
import json
import os
import unittest
import sys
import platform as _plat
import subprocess
from fnmatch import fnmatch

if sys.version_info < (3,):
    str_cls = unicode
    from urllib2 import Request, urlopen, URLError, HTTPError
    from urllib import urlencode
    import cgi
    from io import open
else:
    str_cls = str
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
    from urllib.parse import urlencode


def run(ci=False):
    """
    Runs the tests while measuring coverage

    :param ci:
        If coverage is being run in a CI environment - this triggers trying to
        run the tests for the rest of modularcrypto and uploading coverage data

    :return:
        A bool - if the tests ran successfully
    """

    xml_report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'coverage.xml'))
    if os.path.exists(xml_report_path):
        os.unlink(xml_report_path)

    cov = coverage.Coverage(include='certvalidator/*.py')
    cov.start()

    from .tests import run as run_tests
    result = run_tests()
    print()

    if ci:
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()
        for package_name in []:
            for test_class in _load_package_tests(package_name):
                suite.addTest(loader.loadTestsFromTestCase(test_class))

        if suite.countTestCases() > 0:
            print('Running tests from other modularcrypto packages')
            sys.stdout.flush()
            runner_result = unittest.TextTestRunner(stream=sys.stdout, verbosity=1).run(suite)
            result = runner_result.wasSuccessful() and result
            print()
            sys.stdout.flush()

    cov.stop()
    cov.save()

    cov.report(show_missing=False)
    print()
    sys.stdout.flush()
    if ci:
        cov.xml_report()

    if ci and result and os.path.exists(xml_report_path):
        _codecov_submit()
        print()

    return result


def _load_package_tests(name):
    """
    Load the test classes from another modularcrypto package

    :param name:
        A unicode string of the other package name

    :return:
        A list of unittest.TestCase classes of the tests for the package
    """

    package_dir = os.path.join('..', name)
    if not os.path.exists(package_dir):
        return []

    tests_module_info = imp.find_module('tests', [package_dir])
    tests_module = imp.load_module('%s.tests' % name, *tests_module_info)
    return tests_module.test_classes()


def _codecov_submit():
    if os.getenv('CI') == 'true' and os.getenv('TRAVIS') == 'true':
        # http://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables
        build_url = 'https://travis-ci.org/%s/jobs/%s' % (os.getenv('TRAVIS_REPO_SLUG'), os.getenv('TRAVIS_JOB_ID'))
        query = {
            'service': 'travis',
            'branch': os.getenv('TRAVIS_BRANCH'),
            'build': os.getenv('TRAVIS_JOB_NUMBER'),
            'pr': os.getenv('TRAVIS_PULL_REQUEST'),
            'job': os.getenv('TRAVIS_JOB_ID'),
            'tag': os.getenv('TRAVIS_TAG'),
            'slug': os.getenv('TRAVIS_REPO_SLUG'),
            'commit': os.getenv('TRAVIS_COMMIT'),
            'build_url': build_url,
        }
        root = os.getenv('TRAVIS_BUILD_DIR')

    elif os.getenv('CI') == 'True' and os.getenv('APPVEYOR') == 'True':
        # http://www.appveyor.com/docs/environment-variables
        build_url = 'https://ci.appveyor.com/project/%s/build/%s' % (os.getenv('APPVEYOR_REPO_NAME'), os.getenv('APPVEYOR_BUILD_VERSION'))
        query = {
            'service': "appveyor",
            'branch': os.getenv('APPVEYOR_REPO_BRANCH'),
            'build': os.getenv('APPVEYOR_JOB_ID'),
            'pr': os.getenv('APPVEYOR_PULL_REQUEST_NUMBER'),
            'job': '/'.join((os.getenv('APPVEYOR_ACCOUNT_NAME'), os.getenv('APPVEYOR_PROJECT_SLUG'), os.getenv('APPVEYOR_BUILD_VERSION'))),
            'tag': os.getenv('APPVEYOR_REPO_TAG_NAME'),
            'slug': os.getenv('APPVEYOR_REPO_NAME'),
            'commit': os.getenv('APPVEYOR_REPO_COMMIT'),
            'build_url': build_url,
        }
        root = os.getenv('APPVEYOR_BUILD_FOLDER')

    elif os.getenv('CI') == 'true' and os.getenv('CIRCLECI') == 'true':
        # https://circleci.com/docs/environment-variables
        query = {
            'service': 'circleci',
            'branch': os.getenv('CIRCLE_BRANCH'),
            'build': os.getenv('CIRCLE_BUILD_NUM'),
            'pr': os.getenv('CIRCLE_PR_NUMBER'),
            'job': os.getenv('CIRCLE_BUILD_NUM') + "." + os.getenv('CIRCLE_NODE_INDEX'),
            'tag': os.getenv('CIRCLE_TAG'),
            'slug': os.getenv('CIRCLE_PROJECT_USERNAME') + "/" + os.getenv('CIRCLE_PROJECT_REPONAME'),
            'commit': os.getenv('CIRCLE_SHA1'),
            'build_url': os.getenv('CIRCLE_BUILD_URL'),
        }
        if sys.version_info < (3,):
            root = os.getcwdu()
        else:
            root = os.getcwd()
    else:
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        if not os.path.exists(os.path.join(root, '.git')):
            print('git repository not found, not submitting coverage data')
            return
        git_status = _git_command(['status', '--porcelain'], root)
        if git_status != '':
            print('git repository has uncommitted changes, not submitting coverage data')
            return

        slug = None
        token = None
        try:
            with open(os.path.join(root, 'codecov.json'), 'rb') as f:
                json_data = json.loads(f.read().decode('utf-8'))
                slug = json_data['slug']
                token = json_data['token']
        except (OSError, ValueError, UnicodeDecodeError, KeyError):
            print('error reading codecov.json')
            return

        branch = _git_command(['rev-parse', '--abbrev-ref', 'HEAD'], root)
        commit = _git_command(['rev-parse', '--verify', 'HEAD'], root)
        tag = _git_command(['name-rev', '--tags', '--name-only', commit], root)
        impl = _plat.python_implementation()
        major, minor = _plat.python_version_tuple()[0:2]
        build_name = '%s %s %s.%s' % (_platform_name(), impl, major, minor)
        query = {
            'branch': branch,
            'commit': commit,
            'slug': slug,
            'token': token,
            'build': build_name,
        }
        if tag != 'undefined':
            query['tag'] = tag

    payload = 'PLATFORM=%s\n' % _platform_name()
    payload += 'PYTHON_VERSION=%s %s\n' % (_plat.python_version(), _plat.python_implementation())
    if 'oscrypto' in sys.modules:
        payload += 'OSCRYPTO_BACKEND=%s\n' % sys.modules['oscrypto'].backend()
    payload += '<<<<<< ENV\n'

    for path in _list_files(root):
        payload += path + '\n'
    payload += '<<<<<< network\n'

    payload += '# path=coverage.xml\n'
    with open(os.path.join(root, 'coverage.xml'), 'r', encoding='utf-8') as f:
        payload += f.read() + '\n'
    payload +='<<<<<< EOF\n'

    url = 'https://codecov.io/upload/v4'
    headers = {
        'Accept': 'text/plain'
    }
    filtered_query = {}
    for key in query:
        value = query[key]
        if value == '' or value is None:
            continue
        filtered_query[key] = value

    print('Submitting coverage info to codecov.io')
    info = _do_request(
        'POST',
        url,
        headers,
        query_params=filtered_query
    )

    encoding = info[1] or 'utf-8'
    text = info[2].decode(encoding).strip()
    parts = text.split()
    result, upload_url = parts[0], parts[1]

    headers = {
        'Content-Type': 'text/plain',
        'x-amz-acl': 'public-read',
        'x-amz-storage-class': 'REDUCED_REDUNDANCY'
    }

    print('Uploading coverage data to codecov.io S3 bucket')
    put_info = _do_request(
        'PUT',
        upload_url,
        headers,
        data=payload.encode('utf-8')
    )


def _git_command(params, cwd):
    """
    Executes a git command, returning the output

    :param params:
        A list of the parameters to pass to git

    :param cwd:
        The working directory to execute git in

    :return:
        A 2-element tuple of (stdout, stderr)
    """

    proc = subprocess.Popen(
        ['git'] + params,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd
    )
    stdout, stderr = proc.communicate()
    code = proc.wait()
    if code != 0:
        e = OSError('git exit code was non-zero')
        e.stdout = stdout
        raise e
    return stdout.decode('utf-8').strip()


def _parse_env_var_file(data):
    """
    Parses a basic VAR="value data" file contents into a dict

    :param data:
        A unicode string of the file data

    :return:
        A dict of parsed name/value data
    """

    output = {}
    for line in data.splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        parts = line.split('=')
        if len(parts) != 2:
            continue
        name = parts[0]
        value = parts[1]
        if len(value) > 1:
            if value[0] == '"' and value[-1] == '"':
                value = value[1:-1]
        output[name] = value
    return output


def _platform_name():
    """
    Returns information about the current operating system and version

    :return:
        A unicode string containing the OS name and version
    """

    if sys.platform == 'darwin':
        version = _plat.mac_ver()[0]
        _plat_ver_info = tuple(map(int, version.split('.')))
        if _plat_ver_info < (10, 12):
            name = 'OS X'
        else:
            name = 'macOS'
        return '%s %s' % (name, version)

    elif sys.platform == 'win32':
        _win_ver = sys.getwindowsversion()
        _plat_ver_info = (_win_ver[0], _win_ver[1])
        return 'Windows %s' % _plat.win32_ver()[0]

    elif sys.platform in ['linux', 'linux2']:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r', encoding='utf-8') as f:
                pairs = _parse_env_var_file(f.read())
                if 'NAME' in pairs and 'VERSION_ID' in pairs:
                    return '%s %s' % (pairs['NAME'], pairs['VERSION_ID'])
                    version = pairs['VERSION_ID']
                elif 'PRETTY_NAME' in pairs:
                    return pairs['PRETTY_NAME']
                elif 'NAME' in pairs:
                    return pairs['NAME']
                else:
                    raise ValueError('No suitable version info found in /etc/os-release')
        elif os.path.exists('/etc/lsb-release'):
            with open('/etc/lsb-release', 'r', encoding='utf-8') as f:
                pairs = _parse_env_var_file(f.read())
                if 'DISTRIB_DESCRIPTION' in pairs:
                    return pairs['DISTRIB_DESCRIPTION']
                else:
                    raise ValueError('No suitable version info found in /etc/lsb-release')
        else:
            return 'Linux'

    else:
        return '%s %s' % (_plat.system(), _plat.release())


def _list_files(root):
    """
    Lists all of the files in a directory, taking into account any .gitignore
    file that is present

    :param root:
        A unicode filesystem path

    :return:
        A list of unicode strings, containing paths of all files not ignored
        by .gitignore with root, using relative paths
    """

    dir_patterns, file_patterns = _gitignore(root)
    paths = []
    prefix = os.path.abspath(root) + os.sep
    for base, dirs, files in os.walk(root):
        for d in dirs:
            for dir_pattern in dir_patterns:
                if fnmatch(d, dir_pattern):
                    dirs.remove(d)
                    break
        for f in files:
            skip = False
            for file_pattern in file_patterns:
                if fnmatch(f, file_pattern):
                    skip = True
                    break
            if skip:
                continue
            full_path = os.path.join(base, f)
            if full_path[:len(prefix)] == prefix:
                full_path = full_path[len(prefix):]
            paths.append(full_path)
    return sorted(paths)


def _gitignore(root):
    """
    Parses a .gitignore file and returns patterns to match dirs and files.
    Only basic gitignore patterns are supported. Pattern negation, ** wildcards
    and anchored patterns are not currently implemented.

    :param root:
        A unicode string of the path to the git repository

    :return:
        A 2-element tuple:
         - 0: a list of unicode strings to match against dirs
         - 1: a list of unicode strings to match against dirs and files
    """

    gitignore_path = os.path.join(root, '.gitignore')

    dir_patterns = ['.git']
    file_patterns = []

    if not os.path.exists(gitignore_path):
        return (dir_patterns, file_patterns)

    with open(gitignore_path, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            if '**' in line:
                raise NotImplementedError('gitignore ** wildcards are not implemented')
            if line.startswith('!'):
                raise NotImplementedError('gitignore pattern negation is not implemented')
            if line.startswith('/'):
                raise NotImplementedError('gitignore anchored patterns are not implemented')
            if line.startswith('\\#'):
                line = '#' + line[2:]
            if line.startswith('\\!'):
                line = '!' + line[2:]
            if line.endswith('/'):
                dir_patterns.append(line[:-1])
            else:
                file_patterns.append(line)

    return (dir_patterns, file_patterns)


def _do_request(method, url, headers, data=None, query_params=None, timeout=20):
    """
    Performs an HTTP request

    :param method:
        A unicode string of 'GET', 'POST', 'PUT', or 'DELETE'

    :param url;
        A unicode string of the URL to request

    :param headers:
        A dict of unicode strings, where keys are header names and values are
        the header values.

    :param data:
        A dict of unicode strings (to be encoded as
        application/x-www-form-urlencoded), or a byte string of data.

    :param query_params:
        A dict of unicode keys and values to pass as query params

    :param timeout:
        An integer number of seconds to use as the timeout

    :return:
        A 3-element tuple:
         - 0: A unicode string of the response content-type
         - 1: A unicode string of the response encoding, or None
         - 2: A byte string of the response body
    """

    if query_params:
        url += '?' + urlencode(query_params).replace('+', '%20')

    request = Request(url)
    request.get_method = lambda: method

    if isinstance(data, dict):
        data_bytes = {}
        for key in data:
            data_bytes[key.encode('utf-8')] = data[key].encode('utf-8')
        data = urlencode(data_bytes)
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if isinstance(data, str_cls):
        raise TypeError('data must be a byte string')

    for key in headers:
        value = headers[key]
        if sys.version_info < (3,):
            key = key.encode('iso-8859-1')
            value = value.encode('iso-8859-1')
        request.add_header(key, value)

    response = urlopen(request, data, timeout)
    if sys.version_info < (3,):
        status = response.getcode()
        try:
            content_type, params = cgi.parse_header(response.headers['Content-Type'].strip())
            encoding = params.get('charset')
        except (KeyError):
            content_type = None
            encoding = None
    else:
        status = response.status
        content_type = response.info().get_content_type()
        encoding = response.headers.get_content_charset()
    if status != 200:
        raise HTTPError('Unexpected HTTP %d response' % status)
    return (content_type, encoding, response.read())


if __name__ == '__main__':
    _codecov_submit()
