# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import ast
import _ast
import os
import re
import sys
import textwrap

import commonmark
from collections import OrderedDict

from . import package_name, package_root, md_source_map, definition_replacements


if hasattr(commonmark, 'DocParser'):
    raise EnvironmentError("commonmark must be version 0.6.0 or newer")


def _get_func_info(docstring, def_lineno, code_lines, prefix):
    """
    Extracts the function signature and description of a Python function

    :param docstring:
        A unicode string of the docstring for the function

    :param def_lineno:
        An integer line number that function was defined on

    :param code_lines:
        A list of unicode string lines from the source file the function was
        defined in

    :param prefix:
        A prefix to prepend to all output lines

    :return:
        A 2-element tuple:

         - [0] A unicode string of the function signature with a docstring of
               parameter info
         - [1] A markdown snippet of the function description
    """

    def_index = def_lineno - 1
    definition = code_lines[def_index]
    definition = definition.rstrip()
    while not definition.endswith(':'):
        def_index += 1
        definition += '\n' + code_lines[def_index].rstrip()

    definition = textwrap.dedent(definition).rstrip(':')
    definition = definition.replace('\n', '\n' + prefix)

    description = ''
    found_colon = False

    params = ''

    for line in docstring.splitlines():
        if line and line[0] == ':':
            found_colon = True
        if not found_colon:
            if description:
                description += '\n'
            description += line
        else:
            if params:
                params += '\n'
            params += line

    description = description.strip()
    description_md = ''
    if description:
        description_md = "%s%s" % (prefix, description.replace('\n', '\n' + prefix))
        description_md = re.sub('\n>(\\s+)\n', '\n>\n', description_md)

    params = params.strip()
    if params:
        definition += (':\n%s    """\n%s    ' % (prefix, prefix))
        definition += params.replace('\n', '\n%s    ' % prefix)
        definition += ('\n%s    """' % prefix)
        definition = re.sub('\n>(\\s+)\n', '\n>\n', definition)

    for search, replace in definition_replacements.items():
        definition = definition.replace(search, replace)

    return (definition, description_md)


def _find_sections(md_ast, sections, last, last_class, total_lines=None):
    """
    Walks through a commonmark AST to find section headers that delineate
    content that should be updated by this script

    :param md_ast:
        The AST of the markdown document

    :param sections:
        A dict to store the start and end lines of a section. The key will be
        a two-element tuple of the section type ("class", "function",
        "method" or "attribute") and identifier. The values are a two-element
        tuple of the start and end line number in the markdown document of the
        section.

    :param last:
        A dict containing information about the last section header seen.
        Includes the keys "type_name", "identifier", "start_line".

    :param last_class:
        A unicode string of the name of the last class found - used when
        processing methods and attributes.

    :param total_lines:
        An integer of the total number of lines in the markdown document -
        used to work around a bug in the API of the Python port of commonmark
    """

    def child_walker(node):
        for child, entering in node.walker():
            if child == node:
                continue
            yield child, entering

    for child, entering in child_walker(md_ast):
        if child.t == 'heading':
            start_line = child.sourcepos[0][0]

            if child.level == 2:
                if last:
                    sections[(last['type_name'], last['identifier'])] = (last['start_line'], start_line - 1)
                    last.clear()

            if child.level in set([3, 5]):
                heading_elements = []
                for heading_child, _ in child_walker(child):
                    heading_elements.append(heading_child)
                if len(heading_elements) != 2:
                    continue
                first = heading_elements[0]
                second = heading_elements[1]
                if first.t != 'code':
                    continue
                if second.t != 'text':
                    continue

                type_name = second.literal.strip()
                identifier = first.literal.strip().replace('()', '').lstrip('.')

                if last:
                    sections[(last['type_name'], last['identifier'])] = (last['start_line'], start_line - 1)
                    last.clear()

                if type_name == 'function':
                    if child.level != 3:
                        continue

                if type_name == 'class':
                    if child.level != 3:
                        continue
                    last_class.append(identifier)

                if type_name in set(['method', 'attribute']):
                    if child.level != 5:
                        continue
                    identifier = last_class[-1] + '.' + identifier

                last.update({
                    'type_name': type_name,
                    'identifier': identifier,
                    'start_line': start_line,
                })

        elif child.t == 'block_quote':
            find_sections(child, sections, last, last_class)

    if last:
        sections[(last['type_name'], last['identifier'])] = (last['start_line'], total_lines)


find_sections = _find_sections


def walk_ast(node, code_lines, sections, md_chunks):
    """
    A callback used to walk the Python AST looking for classes, functions,
    methods and attributes. Generates chunks of markdown markup to replace
    the existing content.

    :param node:
        An _ast module node object

    :param code_lines:
        A list of unicode strings - the source lines of the Python file

    :param sections:
        A dict of markdown document sections that need to be updated. The key
        will be a two-element tuple of the section type ("class", "function",
        "method" or "attribute") and identifier. The values are a two-element
        tuple of the start and end line number in the markdown document of the
        section.

    :param md_chunks:
        A dict with keys from the sections param and the values being a unicode
        string containing a chunk of markdown markup.
    """

    if isinstance(node, _ast.FunctionDef):
        key = ('function', node.name)
        if key not in sections:
            return

        docstring = ast.get_docstring(node)
        def_lineno = node.lineno + len(node.decorator_list)

        definition, description_md = _get_func_info(docstring, def_lineno, code_lines, '> ')

        md_chunk = textwrap.dedent("""
            ### `%s()` function

            > ```python
            > %s
            > ```
            >
            %s
        """).strip() % (
            node.name,
            definition,
            description_md
        ) + "\n"

        md_chunks[key] = md_chunk.replace('>\n\n', '')

    elif isinstance(node, _ast.ClassDef):
        if ('class', node.name) not in sections:
            return

        for subnode in node.body:
            if isinstance(subnode, _ast.FunctionDef):
                node_id = node.name + '.' + subnode.name

                method_key = ('method', node_id)
                is_method = method_key in sections

                attribute_key = ('attribute', node_id)
                is_attribute = attribute_key in sections

                is_constructor = subnode.name == '__init__'

                if not is_constructor and not is_attribute and not is_method:
                    continue

                docstring = ast.get_docstring(subnode)
                def_lineno = subnode.lineno
                if sys.version_info < (3, 8):
                    def_lineno += len(subnode.decorator_list)

                if not docstring:
                    continue

                if is_method or is_constructor:
                    definition, description_md = _get_func_info(docstring, def_lineno, code_lines, '> > ')

                    if is_constructor:
                        key = ('class', node.name)

                        class_docstring = ast.get_docstring(node) or ''
                        class_description = textwrap.dedent(class_docstring).strip()
                        if class_description:
                            class_description_md = "> %s\n>" % (class_description.replace("\n", "\n> "))
                        else:
                            class_description_md = ''

                        md_chunk = textwrap.dedent("""
                            ### `%s()` class

                            %s
                            > ##### constructor
                            >
                            > > ```python
                            > > %s
                            > > ```
                            > >
                            %s
                        """).strip() % (
                            node.name,
                            class_description_md,
                            definition,
                            description_md
                        )

                        md_chunk = md_chunk.replace('\n\n\n', '\n\n')

                    else:
                        key = method_key

                        md_chunk = textwrap.dedent("""
                            >
                            > ##### `.%s()` method
                            >
                            > > ```python
                            > > %s
                            > > ```
                            > >
                            %s
                        """).strip() % (
                            subnode.name,
                            definition,
                            description_md
                        )

                    if md_chunk[-5:] == '\n> >\n':
                        md_chunk = md_chunk[0:-5]

                else:
                    key = attribute_key

                    description = textwrap.dedent(docstring).strip()
                    description_md = "> > %s" % (description.replace("\n", "\n> > "))

                    md_chunk = textwrap.dedent("""
                        >
                        > ##### `.%s` attribute
                        >
                        %s
                    """).strip() % (
                        subnode.name,
                        description_md
                    )

                md_chunks[key] = re.sub('[ \\t]+\n', '\n', md_chunk.rstrip())

    elif isinstance(node, _ast.If):
        for subast in node.body:
            walk_ast(subast, code_lines, sections, md_chunks)
        for subast in node.orelse:
            walk_ast(subast, code_lines, sections, md_chunks)


def run():
    """
    Looks through the docs/ dir and parses each markdown document, looking for
    sections to update from Python docstrings. Looks for section headers in
    the format:

     - ### `ClassName()` class
     - ##### `.method_name()` method
     - ##### `.attribute_name` attribute
     - ### `function_name()` function

    The markdown content following these section headers up until the next
    section header will be replaced by new markdown generated from the Python
    docstrings of the associated source files.

    By default maps docs/{name}.md to {modulename}/{name}.py. Allows for
    custom mapping via the md_source_map variable.
    """

    print('Updating API docs...')

    md_files = []
    for root, _, filenames in os.walk(os.path.join(package_root, 'docs')):
        for filename in filenames:
            if not filename.endswith('.md'):
                continue
            md_files.append(os.path.join(root, filename))

    parser = commonmark.Parser()

    for md_file in md_files:
        md_file_relative = md_file[len(package_root) + 1:]
        if md_file_relative in md_source_map:
            py_files = md_source_map[md_file_relative]
            py_paths = [os.path.join(package_root, py_file) for py_file in py_files]
        else:
            py_files = [os.path.basename(md_file).replace('.md', '.py')]
            py_paths = [os.path.join(package_root, package_name, py_files[0])]

            if not os.path.exists(py_paths[0]):
                continue

        with open(md_file, 'rb') as f:
            markdown = f.read().decode('utf-8')

        original_markdown = markdown
        md_lines = list(markdown.splitlines())
        md_ast = parser.parse(markdown)

        last_class = []
        last = {}
        sections = OrderedDict()
        find_sections(md_ast, sections, last, last_class, markdown.count("\n") + 1)

        md_chunks = {}

        for index, py_file in enumerate(py_files):
            py_path = py_paths[index]

            with open(os.path.join(py_path), 'rb') as f:
                code = f.read().decode('utf-8')
                module_ast = ast.parse(code, filename=py_file)
                code_lines = list(code.splitlines())

            for node in ast.iter_child_nodes(module_ast):
                walk_ast(node, code_lines, sections, md_chunks)

        added_lines = 0

        def _replace_md(key, sections, md_chunk, md_lines, added_lines):
            start, end = sections[key]
            start -= 1
            start += added_lines
            end += added_lines
            new_lines = md_chunk.split('\n')
            added_lines += len(new_lines) - (end - start)

            # Ensure a newline above each class header
            if start > 0 and md_lines[start][0:4] == '### ' and md_lines[start - 1][0:1] == '>':
                added_lines += 1
                new_lines.insert(0, '')

            md_lines[start:end] = new_lines
            return added_lines

        for key in sections:
            if key not in md_chunks:
                raise ValueError('No documentation found for %s' % key[1])
            added_lines = _replace_md(key, sections, md_chunks[key], md_lines, added_lines)

        markdown = '\n'.join(md_lines).strip() + '\n'

        if original_markdown != markdown:
            with open(md_file, 'wb') as f:
                f.write(markdown.encode('utf-8'))


if __name__ == '__main__':
    run()
