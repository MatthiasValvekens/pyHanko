# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import ast
import _ast
import os
import sys

from . import package_root, task_keyword_args
from ._import import _import_from


if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


def _list_tasks():
    """
    Fetches a list of all valid tasks that may be run, and the args they
    accept. Does not actually import the task module to prevent errors if a
    user does not have the dependencies installed for every task.

    :return:
        A list of 2-element tuples:
         0: a unicode string of the task name
         1: a list of dicts containing the parameter definitions
    """

    out = []
    dev_path = os.path.join(package_root, 'dev')
    for fname in sorted(os.listdir(dev_path)):
        if fname.startswith('.') or fname.startswith('_'):
            continue
        if not fname.endswith('.py'):
            continue
        name = fname[:-3]
        args = ()

        full_path = os.path.join(package_root, 'dev', fname)
        with open(full_path, 'rb') as f:
            full_code = f.read()
            if sys.version_info >= (3,):
                full_code = full_code.decode('utf-8')

        task_node = ast.parse(full_code, filename=full_path)
        for node in ast.iter_child_nodes(task_node):
            if isinstance(node, _ast.Assign):
                if len(node.targets) == 1 \
                        and isinstance(node.targets[0], _ast.Name) \
                        and node.targets[0].id == 'run_args':
                    args = ast.literal_eval(node.value)
                    break

        out.append((name, args))
    return out


def show_usage():
    """
    Prints to stderr the valid options for invoking tasks
    """

    valid_tasks = []
    for task in _list_tasks():
        usage = task[0]
        for run_arg in task[1]:
            usage += ' '
            name = run_arg.get('name', '')
            if run_arg.get('required', False):
                usage += '{%s}' % name
            else:
                usage += '[%s]' % name
        valid_tasks.append(usage)

    out = 'Usage: run.py'
    for karg in task_keyword_args:
        out += ' [%s=%s]' % (karg['name'], karg['placeholder'])
    out += ' (%s)' % ' | '.join(valid_tasks)

    print(out, file=sys.stderr)
    sys.exit(1)


def _get_arg(num):
    """
    :return:
        A unicode string of the requested command line arg
    """

    if len(sys.argv) < num + 1:
        return None
    arg = sys.argv[num]
    if isinstance(arg, byte_cls):
        arg = arg.decode('utf-8')
    return arg


def run_task():
    """
    Parses the command line args, invoking the requested task
    """

    arg_num = 1
    task = None
    args = []
    kwargs = {}

    # We look for the task name, processing any global task keyword args
    # by setting the appropriate env var
    while True:
        val = _get_arg(arg_num)
        if val is None:
            break

        next_arg = False
        for karg in task_keyword_args:
            if val.startswith(karg['name'] + '='):
                os.environ[karg['env_var']] = val[len(karg['name']) + 1:]
                next_arg = True
                break

        if next_arg:
            arg_num += 1
            continue

        task = val
        break

    if task is None:
        show_usage()

    task_mod = _import_from('dev.%s' % task, package_root, allow_error=True)
    if task_mod is None:
        show_usage()

    run_args = task_mod.__dict__.get('run_args', [])
    max_args = arg_num + 1 + len(run_args)

    if len(sys.argv) > max_args:
        show_usage()

    for i, run_arg in enumerate(run_args):
        val = _get_arg(arg_num + 1 + i)
        if val is None:
            if run_arg.get('required', False):
                show_usage()
            break

        if run_arg.get('cast') == 'int' and val.isdigit():
            val = int(val)

        kwarg = run_arg.get('kwarg')
        if kwarg:
            kwargs[kwarg] = val
        else:
            args.append(val)

    run = task_mod.__dict__.get('run')

    result = run(*args, **kwargs)
    sys.exit(int(not result))
