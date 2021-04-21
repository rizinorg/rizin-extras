# rizin-extras

This repository contains extra plugins for Rizin.

The reasons why these plugins are distributed in a separate
repository are the following:

* Marginal/specific use (ctf-specific assembly/analalysis vm f.ex)
* Rizin must be self-contained (no optional/external deps)
* Simplify how packagers work, and make it more flexible
* Duplicates functionality from Rizin (no need to have
  multiple disassemblers for the same architecture in core)

Depending on the type of the plugin (user or library), the compiled
plugins will be installed at the location `RZ_LIBR_PLUGINS` or `RZ_USER_PLUGINS`
is pointing to. See `rizin -H` for more information about these variables.

Some of the plugins/code don't compile, it will be reviewed
and cleaned up, merged into core, updated or removed.

In addition, this repository will be useful for new contributors
who wants to write their own plugins.

The aim of this repository is to make Rizin's core
to be as concise as possible, reduce the
amount of unnecessary plugins, shrink the install size and
keep it general purpose.

## Building

The recommended way to build and install those plugins for users
is to use rz-pm. See the rz-pm's [repository](https://github.com/rizinorg/rz-pm)