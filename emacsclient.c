// simplified version of emacsclient.c from
// https://github.com/emacs-mirror/emacs/blob/master/lib-src/emacsclient.c

#include <config.h>

#include "syswait.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#define INVALID_SOCKET (-1)
#define HSOCKET int
#define CLOSE_SOCKET close
#define INITIALIZE()

#define egetenv(VAR) getenv(VAR)

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filename.h>
#include <intprops.h>
#include <min-max.h>
#include <pathmax.h>
#include <unlocked-io.h>

/* Work around GCC bug 88251.  */
#if GNUC_PREREQ(7, 0, 0)
#pragma GCC diagnostic ignored "-Wformat-truncation=2"
#endif

/* True means don't wait for a response from Emacs.  --no-wait.  */
static bool nowait;

/* True means don't print messages for successful operations.  --quiet.  */
static bool quiet;

/* True means don't print values returned from emacs. --suppress-output.  */
static bool suppress_output;

/* True means args are expressions to be evaluated.  --eval.  */
static bool eval;

/* True means open a new frame.  --create-frame etc.  */
static bool create_frame;

/* The display on which Emacs should work.  --display.  */
static char const *display;

/* The alternate display we should try if Emacs does not support display.  */
static char const *alt_display;

/* The parent window ID, if we are opening a frame via XEmbed.  */
static char *parent_id;

/* True means open a new Emacs frame on the current terminal.  */
static bool tty;

/* If non-NULL, the name of an editor to fallback to if the server is not
 * running.  --alternate-editor.   */
static char *alternate_editor;

/* If non-NULL, the filename of the UNIX socket.  */
static char const *socket_name;

/* If non-NULL, the filename of the authentication file.  */
static char const *server_file;

/* If non-NULL, the tramp prefix emacs must use to find the files.  */
static char const *tramp_prefix;

/* If nonzero, PID of the Emacs server process.  */
static pid_t emacs_pid;

/* If non-NULL, a string that should form a frame parameter alist to
   be used for the new frame.  */
static char const *frame_parameters;

static _Noreturn void print_help_and_exit(void);

/* Long command-line options.  */

static struct option const longopts[] = {
	{"no-wait", no_argument, NULL, 'n'},
	{"quiet", no_argument, NULL, 'q'},
	{"suppress-output", no_argument, NULL, 'u'},
	{"eval", no_argument, NULL, 'e'},
	{"help", no_argument, NULL, 'H'},
	{"version", no_argument, NULL, 'V'},
	{"tty", no_argument, NULL, 't'},
	{"nw", no_argument, NULL, 't'},
	{"create-frame", no_argument, NULL, 'c'},
	{"alternate-editor", required_argument, NULL, 'a'},
	{"frame-parameters", required_argument, NULL, 'F'},
	{"socket-name", required_argument, NULL, 's'},
	{"server-file", required_argument, NULL, 'f'},
	{"display", required_argument, NULL, 'd'},
	{"parent-id", required_argument, NULL, 'p'},
	{"tramp", required_argument, NULL, 'T'},
	{0, 0, 0, 0}};

/* Short options, in the same order as the corresponding long options.
   There is no '-p' short option.  */
static char const shortopts[] = "nqueHVtca:F:"
	"s:"
	"f:d:T:";

/* From sysdep.c */
#if !defined HAVE_GET_CURRENT_DIR_NAME || defined BROKEN_GET_CURRENT_DIR_NAME

char *get_current_dir_name(void);

/* Return the current working directory.  Returns NULL on errors.
   Any other returned value must be freed with free.  This is used
   only when get_current_dir_name is not defined on the system.  */
char *get_current_dir_name(void) {
	/* The maximum size of a directory name, including the terminating NUL.
	   Leave room so that the caller can append a trailing slash.  */
	ptrdiff_t dirsize_max = min(PTRDIFF_MAX, SIZE_MAX) - 1;

	/* The maximum size of a buffer for a file name, including the
	   terminating NUL.  This is bounded by PATH_MAX, if available.  */
	ptrdiff_t bufsize_max = dirsize_max;
#ifdef PATH_MAX
	bufsize_max = min(bufsize_max, PATH_MAX);
#endif

	struct stat dotstat, pwdstat;
	size_t pwdlen;
	/* If PWD is accurate, use it instead of calling getcwd.  PWD is
	   sometimes a nicer name, and using it may avoid a fatal error if a
	   parent directory is searchable but not readable.  */
	char const *pwd = egetenv("PWD");
	if (pwd && (pwdlen = strnlen(pwd, bufsize_max)) < bufsize_max &&
		IS_DIRECTORY_SEP(pwd[pwdlen && IS_DEVICE_SEP(pwd[1]) ? 2 : 0]) &&
		stat(pwd, &pwdstat) == 0 && stat(".", &dotstat) == 0 &&
		dotstat.st_ino == pwdstat.st_ino && dotstat.st_dev == pwdstat.st_dev)
		return strdup(pwd);
	else {
		ptrdiff_t buf_size = min(bufsize_max, 1024);
		for (;;) {
			char *buf = malloc(buf_size);
			if (!buf)
				return NULL;
			if (getcwd(buf, buf_size) == buf)
				return buf;
			free(buf);
			if (errno != ERANGE || buf_size == bufsize_max)
				return NULL;
			buf_size = buf_size <= bufsize_max / 2 ? 2 * buf_size : bufsize_max;
		}
	}
}
#endif

/* Display a normal or error message.
   On Windows, use a message box if compiled as a Windows app.  */
static void message(bool, const char *, ...) ATTRIBUTE_FORMAT_PRINTF(2, 3);
static void message(bool is_error, const char *format, ...) {
	va_list args;

	va_start(args, format);

	{
		FILE *f = is_error ? stderr : stdout;

		vfprintf(f, format, args);
		fflush(f);
	}

	va_end(args);
}

/* Decode the options from argv and argc.
   The global variable 'optind' will say how many arguments we used up.  */

static void decode_options(int argc, char **argv) {
	alternate_editor = egetenv("ALTERNATE_EDITOR");
	tramp_prefix = egetenv("EMACSCLIENT_TRAMP");

	while (true) {
		int opt = getopt_long_only(argc, argv, shortopts, longopts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 0:
			/* If getopt returns 0, then it has already processed a
			   long-named option.  We should do nothing.  */
			break;

		case 'a':
			alternate_editor = optarg;
			break;

		case 's':
			socket_name = optarg;
			break;

		case 'f':
			server_file = optarg;
			break;

			/* We used to disallow this argument in w32, but it seems better
			   to allow it, for the occasional case where the user is
			   connecting with a w32 client to a server compiled with X11
			   support.  */
		case 'd':
			display = optarg;
			break;

		case 'n':
			nowait = true;
			break;

		case 'e':
			eval = true;
			break;

		case 'q':
			quiet = true;
			break;

		case 'u':
			suppress_output = true;
			break;

		case 'V':
			message(false, "emacsclient %s\n", PACKAGE_VERSION);
			exit(EXIT_SUCCESS);
			break;

		case 't':
			tty = true;
			create_frame = true;
			break;

		case 'c':
			create_frame = true;
			break;

		case 'p':
			parent_id = optarg;
			create_frame = true;
			break;

		case 'H':
			print_help_and_exit();
			break;

		case 'F':
			frame_parameters = optarg;
			break;

		case 'T':
			tramp_prefix = optarg;
			break;

		default:
			message(true, "Try 'emacsclient --help' for more information\n");
			exit(EXIT_FAILURE);
			break;
		}
	}

	/* If the -c option is used (without -t) and no --display argument
	   is provided, try $DISPLAY.
	   Without the -c option, we used to set 'display' to $DISPLAY by
	   default, but this changed the default behavior and is sometimes
	   inconvenient.  So we force users to use "--display $DISPLAY" if
	   they want Emacs to connect to their current display.

	   Some window systems have a notion of default display not
	   reflected in the DISPLAY variable.  If the user didn't give us an
	   explicit display, try this platform-specific after trying the
	   display in DISPLAY (if any).  */
	if (create_frame && !tty && !display)
		display = egetenv("DISPLAY");
}

if (!display)
	display = alt_display;
alt_display = NULL;
}

/* A null-string display is invalid.  */
if (display && !display[0])
	display = NULL;

/* If no display is available, new frames are tty frames.  */
if (create_frame && !display)
	tty = true;
}

static _Noreturn void print_help_and_exit(void) {
	/* Spaces and tabs are significant in this message; they're chosen so the
	   message aligns properly both in a tty and in a Windows message box.
	   Please try to preserve them; otherwise the output is very hard to read
	   when using emacsclientw.  */
	message(
			false, "Usage: emacsclient [OPTIONS] FILE...\n%s%s%s", "\
Tell the Emacs server to visit the specified files.\n\
Every FILE can be either just a FILENAME or [+LINE[:COLUMN]] FILENAME.\n\
\n\
The following OPTIONS are accepted:\n\
-V, --version		Just print version info and return\n\
-H, --help			Print this usage information message\n\
-nw, -t, --tty		Open a new Emacs frame on the current terminal\n\
-c, --create-frame		Create a new frame instead of trying to\n\
			use the current Emacs frame\n\
",
			"\
-F ALIST, --frame-parameters=ALIST\n\
			Set the parameters of a new frame\n\
-e, --eval			Evaluate the FILE arguments as ELisp expressions\n\
-n, --no-wait		Don't wait for the server to return\n\
-q, --quiet		Don't display messages on success\n\
-u, --suppress-output   Don't display return values from the server\n\
-d DISPLAY, --display=DISPLAY\n\
			Visit the file in the given display\n\
",
			"\
--parent-id=ID          Open in parent window ID, via XEmbed\n"
			"-s SOCKET, --socket-name=SOCKET\n\
			Set filename of the UNIX socket for communication\n"
			"-f SERVER, --server-file=SERVER\n\
			Set filename of the TCP authentication file\n\
-a EDITOR, --alternate-editor=EDITOR\n\
			Editor to fallback to if the server is not running\n"
			"			If EDITOR is the empty string, start Emacs in daemon\n\
			mode and try connecting again\n"
			"-T PREFIX, --tramp=PREFIX\n\
						PREFIX to prepend to filenames sent by emacsclient\n\
						for locating files remotely via Tramp\n"
			"\n\
Report bugs with M-x report-emacs-bug.\n");
	exit(EXIT_SUCCESS);
}

static void act_on_signals(HSOCKET);

enum { AUTH_KEY_LENGTH = 64 };

static void ock_err_message(const char *function_name)
	message(true, "emacsclient: %s: %s\n", function_name, strerror(errno));
}

/* Send to S the data in *DATA when either
   - the data's last byte is '\n', or
   - the buffer is full (but this shouldn't happen)
   Otherwise, just accumulate the data.  */
static void send_to_emacs(HSOCKET s, const char *data) {
	enum { SEND_BUFFER_SIZE = 4096 };

	/* Buffer to accumulate data to send in TCP connections.  */
	static char send_buffer[SEND_BUFFER_SIZE + 1];

	/* Fill pointer for the send buffer.  */
	static int sblen;

	for (ptrdiff_t dlen = strlen(data); dlen != 0;) {
		int part = min(dlen, SEND_BUFFER_SIZE - sblen);
		memcpy(&send_buffer[sblen], data, part);
		data += part;
		sblen += part;

		if (sblen == SEND_BUFFER_SIZE ||
			(0 < sblen && send_buffer[sblen - 1] == '\n')) {
			int sent;
			while ((sent = send(s, send_buffer, sblen, 0)) < 0) {
				if (errno != EINTR) {
					message(true, "emacsclient: failed to send %d bytes to socket: %s\n", sblen, strerror(errno));
					exit(EXIT_FAILURE);
				}
				/* Act on signals not requiring communication to Emacs,
				   but defer action on the others to avoid confusing the
				   communication currently in progress.  */
				act_on_signals(INVALID_SOCKET);
			}
			sblen -= sent;
			memmove(send_buffer, &send_buffer[sent], sblen);
		}

		dlen -= part;
	}
}

/* In STR, insert a & before each &, each space, each newline, and
   any initial -.  Change spaces to underscores, too, so that the
   return value never contains a space.

   Does not change the string.  Outputs the result to S.  */
static void quote_argument(HSOCKET s, const char *str) {
	char *copy = malloc(strlen(str) * 2 + 1);
	char *q = copy;
	if (*str == '-')
		*q++ = '&', *q++ = *str++;
	for (; *str; str++) {
		char c = *str;
		if (c == ' ')
			*q++ = '&', c = '_';
		else if (c == '\n')
			*q++ = '&', c = 'n';
		else if (c == '&')
			*q++ = '&';
		*q++ = c;
	}
	*q = 0;

	send_to_emacs(s, copy);

	free(copy);
}

/* The inverse of quote_argument.  Remove quoting in string STR by
   modifying the addressed string in place.  Return STR.  */

static char *unquote_argument(char *str) {
	char const *p = str;
	char *q = str;
	char c;

	do {
		c = *p++;
		if (c == '&') {
			c = *p++;
			if (c == '_')
				c = ' ';
			else if (c == 'n')
				c = '\n';
		}
		*q++ = c;
	} while (c);

	return str;
}

/* If the home directory is HOME, and XDG_CONFIG_HOME's value is XDG,
   return the configuration file with basename CONFIG_FILE.  Fail if
   the configuration file could not be opened.  */

static FILE *open_config(char const *home, char const *xdg,
						 char const *config_file) {
	ptrdiff_t xdgsubdirsize = xdg ? strlen(xdg) + sizeof "/emacs/server/" : 0;
	ptrdiff_t homesuffixsizemax =
		max(sizeof "/.config/emacs/server/", sizeof "/.emacs.d/server/");
	ptrdiff_t homesubdirsizemax = home ? strlen(home) + homesuffixsizemax : 0;
	char *configname =
		malloc(max(xdgsubdirsize, homesubdirsizemax) + strlen(config_file));
	FILE *config;

	if (home) {
		strcpy(stpcpy(stpcpy(configname, home), "/.emacs.d/server/"), config_file);
		config = fopen(configname, "rb");
	} else
		config = NULL;

	if (!config && (xdg || home)) {
		strcpy((xdg ? stpcpy(stpcpy(configname, xdg), "/emacs/server/")
				: stpcpy(stpcpy(configname, home), "/.config/emacs/server/")),
			   config_file);
		config = fopen(configname, "rb");
	}

	free(configname);
	return config;
}

/* Read the information needed to set up a TCP comm channel with
   the Emacs server: host, port, and authentication string.  */

static bool get_server_config(const char *config_file,
							  struct sockaddr_in *server,
							  char *authentication) {
	char dotted[32];
	char *port;
	FILE *config;

	if (IS_ABSOLUTE_FILE_NAME(config_file))
		config = fopen(config_file, "rb");
	else {
		char const *xdg = egetenv("XDG_CONFIG_HOME");
		config = open_config(egetenv("HOME"), xdg, config_file);
	}

	if (!config)
		return false;

	if (fgets(dotted, sizeof dotted, config) && (port = strchr(dotted, ':')))
		*port++ = '\0';
	else {
		message(true, "emacsclient: invalid configuration info\n");
		exit(EXIT_FAILURE);
	}

	memset(server, 0, sizeof *server);
	server->sin_family = AF_INET;
	server->sin_addr.s_addr = inet_addr(dotted);
	server->sin_port = htons(atoi(port));

	if (!fread(authentication, AUTH_KEY_LENGTH, 1, config)) {
		message(true, "emacsclient: cannot read authentication info\n");
		exit(EXIT_FAILURE);
	}

	fclose(config);

	return true;
}

/* Like socket (DOMAIN, TYPE, PROTOCOL), except arrange for the
   resulting file descriptor to be close-on-exec.  */

static HSOCKET cloexec_socket(int domain, int type, int protocol) {
#ifdef SOCK_CLOEXEC
	return socket(domain, type | SOCK_CLOEXEC, protocol);
#else
	HSOCKET s = socket(domain, type, protocol);
	if (0 <= s)
		fcntl(s, F_SETFD, FD_CLOEXEC);
	return s;
#endif
}

static HSOCKET set_tcp_socket(const char *local_server_file) {
	union {
		struct sockaddr_in in;
		struct sockaddr sa;
	} server;
	struct linger l_arg = {.l_onoff = 1, .l_linger = 1};
	char auth_string[AUTH_KEY_LENGTH + 1];

	if (!get_server_config(local_server_file, &server.in, auth_string))
		return INVALID_SOCKET;

	if (server.in.sin_addr.s_addr != inet_addr("127.0.0.1") && !quiet)
		message(false, "emacsclient: connected to remote socket at %s\n", inet_ntoa(server.in.sin_addr));

	/* Open up an AF_INET socket.  */
	HSOCKET s = cloexec_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		/* Since we have an alternate to try out, this is not an error
		   yet; popping out a modal dialog at this stage would make -a
		   option totally useless for emacsclientw -- the user will
		   still get an error message if the alternate editor fails.  */
		sock_err_message("socket");
		return INVALID_SOCKET;
	}

	/* Set up the socket.  */
	if (connect(s, &server.sa, sizeof server.in) != 0) {
		sock_err_message("connect");
		CLOSE_SOCKET(s);
		return INVALID_SOCKET;
	}

	/* The cast to 'const char *' is to avoid a compiler warning when
	   compiling for MS-Windows sockets.  */
	setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&l_arg, sizeof l_arg);

	/* Send the authentication.  */
	auth_string[AUTH_KEY_LENGTH] = '\0';

	send_to_emacs(s, "-auth ");
	send_to_emacs(s, auth_string);
	send_to_emacs(s, " ");

	return s;
}

/* Return true if PREFIX is a prefix of STRING. */
static bool strprefix(const char *prefix, const char *string) {
	return !strncmp(prefix, string, strlen(prefix));
}

/* Get tty name and type.  If successful, store the type into
 *TTY_TYPE and the name into *TTY_NAME, and return true.
 Otherwise, fail if NOABORT is zero, or return false if NOABORT.  */

static bool find_tty(const char **tty_type, const char **tty_name,
					 bool noabort) {
	const char *type = egetenv("TERM");
	const char *name = ttyname(STDOUT_FILENO);

	if (!name) {
		if (noabort)
			return false;
		message(true, "emacsclient: could not get terminal name\n");
		exit(EXIT_FAILURE);
	}

	if (!type) {
		if (noabort)
			return false;
		message(true, "emacsclient: please set the TERM variable to your terminal type\n");
		exit(EXIT_FAILURE);
	}

	const char *inside_emacs = egetenv("INSIDE_EMACS");
	if (inside_emacs && strstr(inside_emacs, ",term:") &&
		strprefix("eterm", type)) {
		if (noabort)
			return false;
		/* This causes nasty, MULTI_KBOARD-related input lockouts. */
		message(true, "emacsclient: opening a frame in an Emacs term buffer is not supported\n");
		exit(EXIT_FAILURE);
	}

	*tty_name = name;
	*tty_type = type;
	return true;
}

/* Return the process group if in the foreground, the negative of the
   process group if in the background, and zero if there is no
   foreground process group for the controlling terminal.
   Unfortunately, use of this function introduces an unavoidable race,
   since whether the process is in the foreground or background can
   change at any time.  */

static pid_t process_grouping(void) {
	pid_t tcpgrp = tcgetpgrp(STDOUT_FILENO);
	if (0 <= tcpgrp) {
		pid_t pgrp = getpgrp();
		return tcpgrp == pgrp ? pgrp : -pgrp;
	}
	return 0;
}

/* Return the file status of NAME, ordinarily a socket.
   It should be owned by UID.  Return one of the following:
   >0 - 'stat' failed with this errno value
   -1 - isn't owned by us
   0 - success: none of the above */

static int socket_status(const char *name, uid_t uid) {
	struct stat statbfr;

	if (stat(name, &statbfr) != 0)
		return errno;

	if (statbfr.st_uid != uid)
		return -1;

	return 0;
}

/* Signal handlers merely set a flag, to avoid race conditions on
   POSIXish systems.  Non-POSIX platforms lacking sigaction make do
   with traditional calls to 'signal'; races are rare so this usually
   works.  Although this approach may treat multiple deliveries of SIG
   as a single delivery and may act on signals in a different order
   than received, that is OK for emacsclient.  Also, this approach may
   omit output if a printf call is interrupted by a signal, but printf
   output is not that important (emacsclient does not check for printf
   errors, after all) so this is also OK for emacsclient.  */

/* Reinstall for SIG the signal handler HANDLER if needed.  It is
   needed on a non-POSIX or traditional platform where an interrupt
   resets the signal handler to SIG_DFL.  */
static void reinstall_handler_if_needed(int sig, void (*handler)(int)) {
#ifndef SA_RESETHAND
	/* This is a platform without POSIX's sigaction.  */
	signal(sig, handler);
#endif
}

/* Flags for each signal, and handlers that set the flags.  */

static sig_atomic_t volatile got_sigcont, got_sigtstp, got_sigttou,
	got_sigwinch;

static void handle_sigcont(int sig) {
	got_sigcont = 1;
	reinstall_handler_if_needed(sig, handle_sigcont);
}
static void handle_sigtstp(int sig) {
	got_sigtstp = 1;
	reinstall_handler_if_needed(sig, handle_sigtstp);
}
static void handle_sigttou(int sig) {
	got_sigttou = 1;
	reinstall_handler_if_needed(sig, handle_sigttou);
}
static void handle_sigwinch(int sig) {
	got_sigwinch = 1;
	reinstall_handler_if_needed(sig, handle_sigwinch);
}

/* Install for signal SIG the handler HANDLER.  However, if FLAG is
   non-null and if the signal is currently being ignored, do not
   install the handler and keep *FLAG zero.  */

static void install_handler(int sig, void (*handler)(int),
							sig_atomic_t volatile *flag) {
#ifdef SA_RESETHAND
	if (flag) {
		struct sigaction oact;
		if (sigaction(sig, NULL, &oact) == 0 && oact.sa_handler == SIG_IGN)
			return;
	}
	struct sigaction act = {.sa_handler = handler};
	sigemptyset(&act.sa_mask);
	sigaction(sig, &act, NULL);
#else
	void (*ohandler)(int) = signal(sig, handler);
	if (flag) {
		if (ohandler == SIG_IGN) {
			signal(sig, SIG_IGN);
			/* While HANDLER was mistakenly installed a signal may have
			   arrived and set *FLAG, so clear *FLAG now.  */
			*flag = 0;
		}
	}
#endif
}

/* Initial installation of signal handlers.  */

static void init_signals(void) {
	install_handler(SIGCONT, handle_sigcont, &got_sigcont);
	install_handler(SIGTSTP, handle_sigtstp, &got_sigtstp);
	install_handler(SIGTTOU, handle_sigttou, &got_sigttou);
	install_handler(SIGWINCH, handle_sigwinch, &got_sigwinch);
	/* Don't mess with SIGINT and SIGQUIT, as Emacs has no way to
	   determine which terminal the signal came from.  C-g is a normal
	   input event on secondary terminals.  */
}

/* Act on delivered tty-related signal SIG that normally has handler
   HANDLER.  EMACS_SOCKET connects to Emacs.  */

static void act_on_tty_signal(int sig, void (*handler)(int),
							  HSOCKET emacs_socket) {
	/* Notify Emacs that we are going to sleep.  Normally the suspend is
	   initiated by Emacs via server-handle-suspend-tty, but if the
	   server gets out of sync with reality, we may get a SIGTSTP on
	   C-z.  Handling this signal and notifying Emacs about it should
	   get things under control again.  */
	send_to_emacs(emacs_socket, "-suspend \n");

	/* Execute the default action by temporarily changing handling to
	   the default and resignaling.  */
	install_handler(sig, SIG_DFL, NULL);
	raise(sig);
	install_handler(sig, handler, NULL);
}

/* Act on delivered signals if possible.  If EMACS_SOCKET is valid,
   use it to communicate to Emacs.  */

static void act_on_signals(HSOCKET emacs_socket) {
	while (true) {
		bool took_action = false;

		if (emacs_socket != INVALID_SOCKET) {
			if (got_sigcont) {
				got_sigcont = 0;
				took_action = true;
				pid_t grouping = process_grouping();
				if (grouping < 0) {
					if (tty) {
						/* Cancel the continue.  */
						kill(grouping, SIGTTIN);
					}
				} else
					send_to_emacs(emacs_socket, "-resume \n");
			}

			if (got_sigtstp) {
				got_sigtstp = 0;
				took_action = true;
				act_on_tty_signal(SIGTSTP, handle_sigtstp, emacs_socket);
			}
			if (got_sigttou) {
				got_sigttou = 0;
				took_action = true;
				act_on_tty_signal(SIGTTOU, handle_sigttou, emacs_socket);
			}
		}

		if (emacs_pid && got_sigwinch) {
			got_sigwinch = 0;
			took_action = true;
			kill(emacs_pid, SIGWINCH);
		}

		if (!took_action)
			break;
	}
}

/* Create in SOCKNAME (of size SOCKNAMESIZE) a name for a local socket.
   The first TMPDIRLEN bytes of SOCKNAME are already initialized to be
   the name of a temporary directory.  Use UID and SERVER_NAME to
   concoct the name.  Return the total length of the name if successful,
   -1 if it does not fit (and store a truncated name in that case).
   Fail if TMPDIRLEN is out of range.  */

static int local_sockname(char *sockname, int socknamesize, int tmpdirlen,
						  uintmax_t uid, char const *server_name) {
	/* If ! (0 <= TMPDIRLEN && TMPDIRLEN < SOCKNAMESIZE) the truncated
	   temporary directory name is already in SOCKNAME, so nothing more
	   need be stored.  */
	if (0 <= tmpdirlen) {
		int remaining = socknamesize - tmpdirlen;
		if (0 < remaining) {
			int suffixlen = snprintf(&sockname[tmpdirlen], remaining,
									 "/emacs%" PRIuMAX "/%s", uid, server_name);
			if (0 <= suffixlen && suffixlen < remaining)
				return tmpdirlen + suffixlen;
		}
	}
	return -1;
}

/* Create a local socket for SERVER_NAME and connect it to Emacs.  If
   SERVER_NAME is a file name component, the local socket name
   relative to a well-known location in a temporary directory.
   Otherwise, the local socket name is SERVER_NAME.  */

static HSOCKET set_local_socket(char const *server_name) {
	union {
		struct sockaddr_un un;
		struct sockaddr sa;
	} server = {{.sun_family = AF_UNIX}};
	char *sockname = server.un.sun_path;
	enum { socknamesize = sizeof server.un.sun_path };
	int tmpdirlen = -1;
	int socknamelen = -1;
	uid_t uid = geteuid();
	bool tmpdir_used = false;

	if (strchr(server_name, '/') || (ISSLASH('\\') && strchr(server_name, '\\')))
		socknamelen = snprintf(sockname, socknamesize, "%s", server_name);
	else {
		/* socket_name is a file name component.  */
		char const *xdg_runtime_dir = egetenv("XDG_RUNTIME_DIR");
		if (xdg_runtime_dir)
			socknamelen = snprintf(sockname, socknamesize, "%s/emacs/%s",
								   xdg_runtime_dir, server_name);
		else {
			char const *tmpdir = egetenv("TMPDIR");
			if (tmpdir)
				tmpdirlen = snprintf(sockname, socknamesize, "%s", tmpdir);
			else {
#ifdef DARWIN_OS
#ifndef _CS_DARWIN_USER_TEMP_DIR
#define _CS_DARWIN_USER_TEMP_DIR 65537
#endif
				size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, sockname, socknamesize);
				if (0 < n && n < (size_t)-1)
					tmpdirlen = min(n - 1, socknamesize);
#endif
				if (tmpdirlen < 0)
					tmpdirlen = snprintf(sockname, socknamesize, "/tmp");
			}
			socknamelen =
				local_sockname(sockname, socknamesize, tmpdirlen, uid, server_name);
			tmpdir_used = true;
		}
	}

	if (!(0 <= socknamelen && socknamelen < socknamesize)) {
		message(true, "emacsclient: socket-name %s... too long\n", sockname);
		exit(EXIT_FAILURE);
	}

	/* See if the socket exists, and if it's owned by us. */
	int sock_status = socket_status(sockname, uid);
	if (sock_status) {
		/* Failing that, see if LOGNAME or USER exist and differ from
		   our euid.  If so, look for a socket based on the UID
		   associated with the name.  This is reminiscent of the logic
		   that init_editfns uses to set the global Vuser_full_name.  */

		char const *user_name = egetenv("LOGNAME");

		if (!user_name)
			user_name = egetenv("USER");

		if (user_name) {
			struct passwd *pw = getpwnam(user_name);

			if (pw && pw->pw_uid != uid) {
				/* We're running under su, apparently. */
				socknamelen = local_sockname(sockname, socknamesize, tmpdirlen,
											 pw->pw_uid, server_name);
				if (socknamelen < 0) {
					message(true, "emacsclient: socket-name %s... too long\n", sockname);
					exit(EXIT_FAILURE);
				}

				sock_status = socket_status(sockname, uid);
			}
		}
	}

	if (sock_status == 0) {
		HSOCKET s = cloexec_socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0) {
			message(true, "emacsclient: socket: %s\n", strerror(errno));
			return INVALID_SOCKET;
		}
		if (connect(s, &server.sa, sizeof server.un) != 0) {
			message(true, "emacsclient: connect: %s\n", strerror(errno));
			CLOSE_SOCKET(s);
			return INVALID_SOCKET;
		}

		struct stat connect_stat;
		if (fstat(s, &connect_stat) != 0)
			sock_status = errno;
		else if (connect_stat.st_uid == uid)
			return s;
		else
			sock_status = -1;

		CLOSE_SOCKET(s);
	}

	if (sock_status < 0)
		message(true, "emacsclient: Invalid socket owner\n");
	else if (sock_status == ENOENT) {
		if (tmpdir_used) {
			uintmax_t id = uid;
			char sockdirname[socknamesize];
			int sockdirnamelen =
				snprintf(sockdirname, sizeof sockdirname, "/run/user/%" PRIuMAX, id);
			if (0 <= sockdirnamelen && sockdirnamelen < sizeof sockdirname &&
				faccessat(AT_FDCWD, sockdirname, X_OK, AT_EACCESS) == 0)
				message(true, "emacsclient: Should XDG_RUNTIME_DIR='%s' be in the environment?\nemacsclient: (Be careful: XDG_RUNTIME_DIR is security-related.)\n",	sockdirname);
		}

		/* If there's an alternate editor and the user has requested
		   --quiet, don't output the warning. */
		if (!quiet || !alternate_editor) {
			message(true, "emacsclient: can't find socket; have you started the server?\nTo start the server in Emacs, type \"M-x server-start\".\n");
		}
	} else
		message(true, "emacsclient: can't stat %s: %s\n", sockname, strerror(sock_status));

	return INVALID_SOCKET;
}

static HSOCKET set_socket(bool no_exit_if_error) {
	HSOCKET s;
	const char *local_server_file = server_file;

	INITIALIZE();

	if (!socket_name)
		socket_name = egetenv("EMACS_SOCKET_NAME");

	if (socket_name) {
		/* Explicit --socket-name argument, or environment variable.  */
		s = set_local_socket(socket_name);
		if (s != INVALID_SOCKET || no_exit_if_error)
			return s;
		message(true, "emacsclient: error accessing socket \"%s\"\n", socket_name);
		exit(EXIT_FAILURE);
	}

	/* Explicit --server-file arg or EMACS_SERVER_FILE variable.  */
	if (!local_server_file)
		local_server_file = egetenv("EMACS_SERVER_FILE");

	if (local_server_file) {
		s = set_tcp_socket(local_server_file);
		if (s != INVALID_SOCKET || no_exit_if_error)
			return s;

		message(true, "emacsclient: error accessing server file \"%s\"\n", local_server_file);
		exit(EXIT_FAILURE);
	}

	/* Implicit local socket.  */
	s = set_local_socket("server");
	if (s != INVALID_SOCKET)
		return s;

	/* Implicit server file.  */
	s = set_tcp_socket("server");
	if (s != INVALID_SOCKET || no_exit_if_error)
		return s;

	/* No implicit or explicit socket, and no alternate editor.  */
	message(true,
			"emacsclient: No socket or alternate editor.  Please use:\n\n"
			"\t--socket-name\n"
			"\t--server-file      (or environment variable EMACS_SERVER_FILE)\n\
\t--alternate-editor (or environment variable ALTERNATE_EDITOR)\n");
	exit(EXIT_FAILURE);
}

/* Start the emacs daemon and try to connect to it.  */

static HSOCKET start_daemon_and_retry_set_socket(void) {
	pid_t dpid;
	int status;

	dpid = fork();

	if (dpid > 0) {
		pid_t w = waitpid(dpid, &status, WUNTRACED | WCONTINUED);

		if (w < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			message(true, "Error: Could not start the Emacs daemon\n");
			exit(EXIT_FAILURE);
		}

		/* Try connecting, the daemon should have started by now.  */
		message(true,
				"Emacs daemon should have started, trying to connect again\n");
	} else if (dpid < 0) {
		fprintf(stderr, "Error: Cannot fork!\n");
		exit(EXIT_FAILURE);
	} else {
		char emacs[] = "emacs";
		char daemon_option[] = "--daemon";
		char *d_argv[3];
		d_argv[0] = emacs;
		d_argv[1] = daemon_option;
		d_argv[2] = 0;
		if (socket_name != NULL) {
			/* Pass  --daemon=socket_name as argument.  */
			const char *deq = "--daemon=";
			char *daemon_arg = malloc(strlen(deq) + strlen(socket_name) + 1);
			strcpy(stpcpy(daemon_arg, deq), socket_name);
			d_argv[1] = daemon_arg;
		}
		execvp("emacs", d_argv);
		message(true, "emacsclient: error starting emacs daemon\n");
		exit(EXIT_FAILURE);
	}

	HSOCKET emacs_socket = set_socket(true);
	if (emacs_socket == INVALID_SOCKET) {
		message(true,
				"Error: Cannot connect even after starting the Emacs daemon\n");
		exit(EXIT_FAILURE);
	}
	return emacs_socket;
}

int main(int argc, char **argv) {
	int rl = 0;
	bool skiplf = true;
	char string[BUFSIZ + 1];
	int exit_status = EXIT_SUCCESS;

	/* Process options.  */
	decode_options(argc, argv);

	if (!(optind < argc || eval || create_frame)) {
		message(true, "emacsclient: file name or argument required\nTry 'emacsclient --help' for more information\n");
		exit(EXIT_FAILURE);
	}

	if (tty) {
		pid_t grouping = process_grouping();
		if (grouping < 0)
			kill(grouping, SIGTTIN);
	}

	/* If alternate_editor is the empty string, start the emacs daemon
	   in case of failure to connect.  */
	bool start_daemon_if_needed = alternate_editor && !alternate_editor[0];

	HSOCKET emacs_socket = set_socket(alternate_editor || start_daemon_if_needed);
	if (emacs_socket == INVALID_SOCKET) {
		if (!start_daemon_if_needed)
			exit(EXIT_FAILURE);

		emacs_socket = start_daemon_and_retry_set_socket();
	}

	char *cwd = get_current_dir_name();
	if (cwd == 0) {
		message(true, "emacsclient: Cannot get current working directory\n");
		exit(EXIT_FAILURE);
	}

	/* Send over our environment and current directory. */
	if (create_frame) {
		for (char *const *e = environ; *e; e++) {
			send_to_emacs(emacs_socket, "-env ");
			quote_argument(emacs_socket, *e);
			send_to_emacs(emacs_socket, " ");
		}
	}
	send_to_emacs(emacs_socket, "-dir ");
	if (tramp_prefix)
		quote_argument(emacs_socket, tramp_prefix);
	quote_argument(emacs_socket, cwd);
	free(cwd);
	send_to_emacs(emacs_socket, "/");
	send_to_emacs(emacs_socket, " ");

 retry:
	if (nowait)
		send_to_emacs(emacs_socket, "-nowait ");

	if (!create_frame)
		send_to_emacs(emacs_socket, "-current-frame ");

	if (display) {
		send_to_emacs(emacs_socket, "-display ");
		quote_argument(emacs_socket, display);
		send_to_emacs(emacs_socket, " ");
	}

	if (parent_id) {
		send_to_emacs(emacs_socket, "-parent-id ");
		quote_argument(emacs_socket, parent_id);
		send_to_emacs(emacs_socket, " ");
	}

	if (frame_parameters && create_frame) {
		send_to_emacs(emacs_socket, "-frame-parameters ");
		quote_argument(emacs_socket, frame_parameters);
		send_to_emacs(emacs_socket, " ");
	}

	/* Unless we are certain we don't want to occupy the tty, send our
	   tty information to Emacs.  For example, in daemon mode Emacs may
	   need to occupy this tty if no other frame is available.  */
	if (create_frame || !eval) {
		const char *tty_type, *tty_name;

		if (find_tty(&tty_type, &tty_name, !tty)) {
			/* Install signal handlers before opening a frame on the
			   current tty.  */
			init_signals();

			send_to_emacs(emacs_socket, "-tty ");
			quote_argument(emacs_socket, tty_name);
			send_to_emacs(emacs_socket, " ");
			quote_argument(emacs_socket, tty_type);
			send_to_emacs(emacs_socket, " ");
		}
	}

	if (create_frame && !tty)
		send_to_emacs(emacs_socket, "-window-system ");

	if (optind < argc) {
		for (int i = optind; i < argc; i++) {

			if (eval) {
				/* Don't prepend cwd or anything like that.  */
				send_to_emacs(emacs_socket, "-eval ");
				quote_argument(emacs_socket, argv[i]);
				send_to_emacs(emacs_socket, " ");
				continue;
			}

			char *p = argv[i];
			if (*p == '+') {
				unsigned char c;
				do
					c = *++p;
				while (isdigit(c) || c == ':');

				if (c == 0) {
					send_to_emacs(emacs_socket, "-position ");
					quote_argument(emacs_socket, argv[i]);
					send_to_emacs(emacs_socket, " ");
					continue;
				}
			}

			send_to_emacs(emacs_socket, "-file ");
			if (tramp_prefix && IS_ABSOLUTE_FILE_NAME(argv[i]))
				quote_argument(emacs_socket, tramp_prefix);
			quote_argument(emacs_socket, argv[i]);
			send_to_emacs(emacs_socket, " ");
		}
	} else if (eval) {
		/* Read expressions interactively.  */
		while (fgets(string, BUFSIZ, stdin)) {
			send_to_emacs(emacs_socket, "-eval ");
			quote_argument(emacs_socket, string);
		}
		send_to_emacs(emacs_socket, " ");
	}

	send_to_emacs(emacs_socket, "\n");

	/* Wait for an answer. */
	if (!eval && !tty && !nowait && !quiet && 0 <= process_grouping()) {
		printf("Waiting for Emacs...");
		skiplf = false;
	}
	fflush(stdout);

	/* Now, wait for an answer and print any messages.  */
	while (exit_status == EXIT_SUCCESS) {
		do {
			act_on_signals(emacs_socket);
			rl = recv(emacs_socket, string, BUFSIZ, 0);
		} while (rl < 0 && errno == EINTR);

		if (rl <= 0)
			break;

		string[rl] = '\0';

		/* Loop over all NL-terminated messages.  */
		char *p = string;
		for (char *end_p = p; end_p && *end_p != '\0'; p = end_p) {
			end_p = strchr(p, '\n');
			if (end_p != NULL)
				*end_p++ = '\0';

			if (strprefix("-emacs-pid ", p)) {
				/* -emacs-pid PID: The process id of the Emacs process. */
				emacs_pid = strtoumax(p + strlen("-emacs-pid"), NULL, 10);
			} else if (strprefix("-window-system-unsupported ", p)) {
				/* -window-system-unsupported: Emacs was compiled without support
				   for whatever window system we tried.  Try the alternate
				   display, or, failing that, try the terminal.  */
				if (alt_display) {
					display = alt_display;
					alt_display = NULL;
				} else {
					nowait = false;
					tty = true;
				}

				goto retry;
			} else if (strprefix("-print ", p)) {
				/* -print STRING: Print STRING on the terminal. */
				if (!suppress_output) {
					char *str = unquote_argument(p + strlen("-print "));
					printf(&"\n%s"[skiplf], str);
					if (str[0])
						skiplf = str[strlen(str) - 1] == '\n';
				}
			} else if (strprefix("-print-nonl ", p)) {
				/* -print-nonl STRING: Print STRING on the terminal.
				   Used to continue a preceding -print command.  */
				if (!suppress_output) {
					char *str = unquote_argument(p + strlen("-print-nonl "));
					printf("%s", str);
					if (str[0])
						skiplf = str[strlen(str) - 1] == '\n';
				}
			} else if (strprefix("-error ", p)) {
				/* -error DESCRIPTION: Signal an error on the terminal. */
				char *str = unquote_argument(p + strlen("-error "));
				if (!skiplf)
					printf("\n");
				fprintf(stderr, "*ERROR*: %s", str);
				if (str[0])
					skiplf = str[strlen(str) - 1] == '\n';
				exit_status = EXIT_FAILURE;
			} else if (strprefix("-suspend ", p)) {
				/* -suspend: Suspend this terminal, i.e., stop the process. */
				if (!skiplf)
					printf("\n");
				skiplf = true;
				kill(0, SIGSTOP);
			} else {
				/* Unknown command. */
				printf(&"\n*ERROR*: Unknown message: %s\n"[skiplf], p);
				skiplf = true;
			}
		}
	}

	if (!skiplf && 0 <= process_grouping())
		printf("\n");

	if (rl < 0)
		exit_status = EXIT_FAILURE;

	CLOSE_SOCKET(emacs_socket);
	return exit_status;
}
