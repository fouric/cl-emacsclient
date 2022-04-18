Currently hosting my reverse-engineering efforts of emacsclient.c - the protocol isn't explicitly documented anywhere.

# Questions
- Does act_on_signals actually pass on some signals to the emacs instance it's connected to? Why? Would any major harm come of *not* passing them on?
- What kind of socket/connection is used to communicate with Emacs?
- Why is there a random block scope in message()?
- How can we detect that SOCK_CLOEXEC is available on the given platform?
- How do we do SOCK_CLOEXEC in a dynamic language i.e. CL?

# Todo
- Actually try to compile this and use it to talk to Emacs
- Port over quote_argument() and unquote_argument() to CL and test on their own before any integration

# Workspace

`HSOCKET emacs_socket = set_socket();` is where the socket itself comes from.
HSOCKET is just an int.