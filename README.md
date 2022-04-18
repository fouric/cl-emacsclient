Currently hosting my reverse-engineering efforts of emacsclient.c - the protocol isn't explicitly documented anywhere.

# Questions
- Does act_on_signals actually pass on some signals to the emacs instance it's connected to? Why? Would any major harm come of *not* passing them on?
- What kind of socket/connection is used to communicate with Emacs?

# Todo
- Actually try to compile this and use it to talk to Emacs.

# Workspace

`HSOCKET emacs_socket = set_socket();` is where the socket itself comes from.
HSOCKET is just an int.