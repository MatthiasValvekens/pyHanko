.. _cli-plugin-dev:

Developing CLI plugins
======================

.. versionadded:: 0.18.0

.. |Signer| replace:: :class:`~pyhanko.sign.signers.pdf_cms.Signer`
.. |SigningCommandPlugin| replace:: :class:`~pyhanko.cli.plugin_api.SigningCommandPlugin`


.. warning::
    This is an incubating feature. API adjustments are still possible.


Since version ``0.18.0``, pyHanko's CLI can load |Signer| implementations
from external sources with minimal configuration.

If you develop an integration for a remote signing service or hardware
device that isn't already supported by the pyHanko CLI out of the box,
you can make your implementation available to CLI users as a separate
package. If you set things up the right way, all your users have to do
is install it, and pyHanko will automagically detect the plugin.

This page aims to provide you with some pointers to upgrade your
|Signer| implementation into a CLI-integrated plugin.

.. note::
    Plugins are only supported on Python 3.8 and up.


General principles
------------------

Throughout, we assume that you have a |Signer| implementation that you
want to hook into the CLI. This could be an
:ref:`integration that you developed yourself <extending-signer>`,
or simply a wrapper around an existing |Signer| to facilitate integration
with some third-party service or a particular hardware device.
Anything goes.

In order to help you write the necessary glue code to patch things into
the CLI, we'll go over the following:

 * how to provide the mapping between CLI arguments and instances of your |Signer|;
 * how to get access to other parts of the CLI context (e.g. configuration settings);
 * how to ensure that the ``pyhanko`` executable picks up your plugin.


The plugin API
--------------

Implementation-wise, all you have to do is implement the
|SigningCommandPlugin| interface. This will provide the link between
pyHanko's ``click``-based CLI and your custom |Signer|.

This is what the basic skeleton looks like.

.. code-block:: python

    class MySigningCommand(SigningCommandPlugin):
        subcommand_name = 'mysigner'
        help_summary = 'a short line about the plugin'

        def click_options(self) -> List[click.Option]:
            ...

        def create_signer(
            self, context: CLIContext, **kwargs
        ) -> ContextManager[Signer]:
            ...


The :attr:`~pyhanko.cli.plugin_api.SigningCommandPlugin.subcommand_name`
and :attr:`~pyhanko.cli.plugin_api.SigningCommandPlugin.help_summary`
attributes are self-explanatory: they respectively provide the name
and help text for the subcommand to ``addsig`` that's being added by
your plugin.

The :meth:`~pyhanko.cli.plugin_api.SigningCommandPlugin.click_options` method
provides the ``click`` options to your plugin's subcommand. For more details
on how to define options
see `the Click documentation <https://click.palletsprojects.com/en/latest/api/#click.Option>`_.

As an example, the options for a simplified version of the ``pkcs11`` subcommand
in pyHanko's CLI could've been defined as follows.

.. code-block:: python

    def click_options(self) -> List[click.Option]:
        return [
            click.Option(
                ('--lib',),
                help='path to PKCS#11 module',
                type=readable_file,
                required=False,
            ),
            click.Option(
                ('--token-label',),
                help='PKCS#11 token label',
                type=str,
                required=False,
            ),
            click.Option(
                ('--cert-label',),
                help='certificate label',
                type=str,
                required=False,
            ),
            click.Option(
                ('--key-label',), help='key label', type=str, required=False
            ),
        ]


The core plumbing for your plugin will be supplied in the
:meth:`~pyhanko.cli.plugin_api.SigningCommandPlugin.create_signer` method.

Here's a brief rundown of what the arguments mean.

 * The ``context`` parameter supplies the current
   :class:`~pyhanko.cli.plugin_api.CLIContext`, which in particular
   exposes access to the contents of the config file (if any).
 * The remaining keyword arguments are wired through directly
   from ``click``, and will correspond to the options you defined in
   :meth:`~pyhanko.cli.plugin_api.SigningCommandPlugin.click_options`.

Note that the return type of
:meth:`~pyhanko.cli.plugin_api.SigningCommandPlugin.create_signer` is
not just a |Signer|, but a context manager wrapping a |Signer|.
This allows pyHanko to easily return control to the plugin after signing or
when errors are thrown, so that the plugin code can run its own
teardown logic.

.. warning::
    The plugin class must have a no-arguments ``__init__`` method.


Plugin discovery and registration
---------------------------------


Using a package entry points
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The easiest way to make your plugin discoverable is to package it
with a `package entry point <https://setuptools.pypa.io/en/latest/userguide/entry_point.html>`_
for pyHanko CLI plugins. The entry point group ID is ``pyhanko.cli_plugin.signing``.
If you manage your plugin's packaging metadata with ``pyproject.toml``,
this is all you have to add:

.. code-block:: toml

    [project.entry-points."pyhanko.cli_plugin.signing"]
    your_plugin = "some_package.path.to.module:SomePluginClass"

With entry points set up, pyHanko will automatically discover your plugin if it's
installed (i.e. if ``importlib`` can find it).


From the configuration file
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you don't want to use packages or can't for some reason,
you also have the option to reference them from pyHanko's configuration
file, like so:

.. code-block:: yaml

    plugins:
        - some_package.path.to.module:SomePluginClass
