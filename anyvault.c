/*
 *  anyvault -- a command-line password manager.
 *
 *  Copyright (C) 2019-2025 Pascal Lalonde <plalonde@overnet.ca>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <jansson.h>

#include <wchar.h>
#include <wctype.h>
#include <locale.h>

#include <X11/XKBlib.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>

const char  program_name[] = PROGNAME;
const char *version = VERSION;

char    cfg_path[PATH_MAX] = "";
int     timeout = 300;
size_t  max_value_length = 16384;
int     no_mlock = 0;
int     permission_check = 1;
int     enable_core = 0;
int     debug_level = 0;
char   *encrypt_cmd = NULL;
char   *decrypt_cmd = NULL;
char   *backup_cmd = NULL;
char   *paste_cmd = NULL;
char   *xtype_hotkey = "F11";
char   *xtype_esc = "Escape";

int     db_backup_done = 0;
json_t *db = NULL;

struct termios saved_termios;

volatile sig_atomic_t timed_out = 0;
volatile sig_atomic_t in_readline = 0;

const char *fields[] = { "notes", "url", "login", "secret", NULL };

void save_db();

void
print_help()
{
	printf("Usage: %s [options]\n", program_name);
	printf("\t-h\t\t\tPrint this help\n");
	printf("\t-v\t\t\tPrint version\n");
	printf("\t-d\t\t\tIncrease debuggging output\n");
	printf("\t-c\t<cfg path>\tUse an alternate path for the configuration;\n");
	printf("\t\t\t\tDefault is %s\n", cfg_path);
	printf("\t-x\t\t\tSkip permission and ownership checks (insecure)\n");
	printf("\t-X\t\t\tDon't disable core dump creation (insecure)\n");
}

/*
 * Used to track how much mlock'd memory we have. Used for reporting only.
 */
static size_t locked_allocated = 0;

/*
 * Allocates and mlock()'s memory and saves how many bytes are allocatable,
 * to be used when deallocating to wipe and munlock() the right amount
 * of memory. Adds an extra sizeof(size_t) at the start of the block.
 */
void *
locked_mem(size_t s)
{
	void *p;

	p = malloc(sizeof(s) + s);
	if (p == NULL)
		return NULL;

	*((size_t *)p) = s;

	if (!no_mlock) {
		if (mlock(p, sizeof(s) + s) == -1) {
			warn("not allocating %lu bytes; mlock", s);
			warnx("currently locked: %lu bytes", locked_allocated);
			free(p);
			return NULL;
		}
		locked_allocated += sizeof(s) + s;
		if (debug_level >= 2)
			warnx("current locked memory: %lu bytes",
			    locked_allocated);
	}

	return (char *)p + sizeof(s);
}

/*
 * Opposite to locked_mem(), this overwrites to-be-freed memory with zeroes
 * calls munlock() and finally frees the memory. The amount of bytes
 * is saved at (buf - sizeof(size_t)).
 */
void
wipe_mem(void *buf)
{
	size_t  len;
	void   *p;

	if (buf == NULL)
		return;

	p = (char *)buf - sizeof(len);
	len = *((size_t *)p);

	explicit_bzero(buf, len);

	if (!no_mlock) {
		if (munlock(p, len + sizeof(len)) == -1)
			warn("munlock");
		else
			locked_allocated -= len + sizeof(len);
		if (debug_level >= 2)
			warnx("current locked memory: %lu bytes",
			    locked_allocated);
	}
	free(p);
}

void
restore_termios()
{
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
}

static size_t
load_json(void *buf, size_t bufsz, void *data)
{
	int     fd = *(int *)data;
	size_t  offset = 0;
	ssize_t r;

	for (;;) {
		r = read(fd, buf + offset, bufsz - offset);
		if (r == -1) {
			if (errno == EINTR && !timed_out)
				continue;
			warn("%s: read", __func__);
			return (size_t)-1;
		}
		if (r == 0)
			break;
		offset += r;
	}
	return offset;
}

int
dump_json(const char *buf, size_t bufsz, void *data)
{
	int     fd = *(int *)data;
	size_t  offset = 0;
	ssize_t r;

	while (offset < bufsz) {
		r = write(fd, buf + offset, bufsz - offset);
		if (r == -1) {
			if (errno == EINTR && !timed_out)
				continue;
			warn("%s: write", __func__);
			return -1;
		}
		offset += r;
	}
	return 0;
}

char **
str_split(const char *str)
{
	int          parts, in_word;
	const char  *cp = str;
	char        *p;
	char       **array, **ap;

	for (parts = 0, in_word = 0, cp = str; *cp != '\0'; cp++) {
		if (!isspace(*cp) && !in_word) {
			parts++;
			in_word = 1;
		} else if (isspace(*cp) && in_word)
			in_word = 0;
	}

	array = malloc(((parts + 1) * sizeof(char *)) + (strlen(str) + 1));
	if (array == NULL)
		return NULL;
	array[parts] = NULL;
	p = ((char *)array) + ((parts + 1) * sizeof(char *));
	memcpy(p, str, strlen(str) + 1);

	for (ap = array, in_word = 0; *p != '\0'; p++) {
		if (!isspace(*p) && !in_word) {
			in_word = 1;
			*ap++ = p;
		} else if (isspace(*p) && in_word) {
			*p = '\0';
			in_word = 0;
		}
	}

	return array;
}

int
spawn(char *const program[])
{
	pid_t            pid;
	struct sigaction act;
	int              null_fd;
	int              err_fd = dup(STDERR_FILENO);
	int              status;

	if (err_fd == -1) {
		warn("dup");
		return -1;
	}
	if (fcntl(err_fd, F_SETFD, FD_CLOEXEC) == -1) {
		warn("fcntl");
		close(err_fd);
		return -1;
	}

	if ((pid = fork()) == -1) {
		warn("fork");
		return -1;
	} else if (pid == 0) {
		bzero(&act, sizeof(act));
		act.sa_handler = SIG_DFL;
		if (sigaction(SIGTERM, &act, NULL) == -1) {
			warn("sigaction");
			_exit(1);
		}

		if (chdir("/") == -1) {
			warn("chdir");
			_exit(1);
		}

		if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
			warn("open");
			_exit(1);
		}

		if (dup2(null_fd, STDIN_FILENO) == -1) {
			warn("dup2");
			_exit(1);
		}
		if (dup2(null_fd, STDOUT_FILENO) == -1) {
			warn("dup2");
			_exit(1);
		}
		if (dup2(null_fd, STDERR_FILENO) == -1) {
			warn("dup2");
			_exit(1);
		}
		if (null_fd > 2)
			close(null_fd);

		if (err_fd != 3) {
			if (dup2(err_fd, 3) == -1) {
				/* No way to print anything to stderr now. */
				_exit(127);
			}
			close(err_fd);
			err_fd = 3;
		}

		closefrom(4);

		if (execv(program[0], program) == -1) {
			dprintf(err_fd, "execv: %s: %s\n",
			    program[0], strerror(errno));
			_exit(1);
		}
	}
	close(err_fd);
again:
	if (waitpid(pid, &status, 0) == -1) {
		if (errno == EINTR && !timed_out)
			goto again;
		warn("waitpid");
		return -1;
	}
	return status;
}

int
safe_popen(char *const program[], int write_end, int cloexec, pid_t *pid)
{
	int              fd;
	int              p_io[2];
	int              null_fd;
	struct sigaction act;
	int              err_fd = dup(STDERR_FILENO);

	if (err_fd == -1) {
		warn("dup");
		return -1;
	}
	if (fcntl(err_fd, F_SETFD, FD_CLOEXEC) == -1) {
		warn("fcntl");
		close(err_fd);
		return -1;
	}

	tcflush(STDIN_FILENO, TCIFLUSH);

	if (pipe(p_io) == -1) {
		warn("pipe");
		return -1;
	}

	if ((*pid = fork()) == -1) {
		warn("fork");
		close(p_io[0]);
		close(p_io[1]);
		close(err_fd);
		return -1;
	} else if (*pid == 0) {
		bzero(&act, sizeof(act));
		act.sa_handler = SIG_DFL;
		if (sigaction(SIGTERM, &act, NULL) == -1) {
			warn("sigaction");
			_exit(1);
		}

		if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
			warn("open");
			_exit(1);
		}

		/*
		 * Parent wants a write-end pipe, so as the child
		 * we have to close p_io[1] and assign p_io[0] to
		 * our stdin.
		 */
		if (write_end) {
			if (dup2(null_fd, STDOUT_FILENO) == -1) {
				warn("dup2");
				_exit(1);
			}
			if (dup2(p_io[0], STDIN_FILENO) == -1) {
				warn("dup2");
				_exit(1);
			}
			close(p_io[1]);
		} else {
			if (dup2(null_fd, STDIN_FILENO) == -1) {
				warn("dup2");
				_exit(1);
			}
			if (dup2(p_io[1], STDOUT_FILENO) == -1) {
				warn("dup2");
				_exit(1);
			}
			close(p_io[0]);
		}

		if (chdir("/") == -1) {
			warn("chdir");
			_exit(1);
		}

		if (dup2(null_fd, STDERR_FILENO) == -1) {
			warn("dup2");
			_exit(1);
		}

		if (null_fd > 2)
			close(null_fd);

		/*
		 * We want to keep only stdin/out/err, and err_fd. Anything
		 * else is something that shouldn't be in the child.
		 */
		if (err_fd != 3) {
			if (dup2(err_fd, 3) == -1) {
				/* No way to print anything to stderr now. */
				_exit(127);
			}
			close(err_fd);
			err_fd = 3;
		}
		closefrom(4);

		if (execv(program[0], program) == -1) {
			dprintf(err_fd, "execv: %s: %s\n",
			    program[0], strerror(errno));
			_exit(1);
		}
	}

	close(err_fd);
	if (write_end) {
		fd = p_io[1];
		close(p_io[0]);
	} else {
		fd = p_io[0];
		close(p_io[1]);
	}

	if (cloexec && fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		warn("fcntl");
		close(fd);
		return -1;
	}

	return fd;
}

char *
str_replace(const char *str, const char *search, const char *replace)
{
	const char *pos, *prev;
	char       *result, *saved;
	size_t      search_len;

	if (search == NULL)
		return strdup(str);

	pos = strstr(str, search);
	if (pos == NULL)
		return strdup(str);

	search_len = strlen(search);
	result = NULL;
	prev = NULL;

	if (asprintf(&result, "%.*s%s", (int)(pos - str), str, replace) == -1)
		return NULL;
	prev = pos + search_len;
	saved = result;

	while ((pos = strstr(prev, search))) {
		if (asprintf(&result, "%s%.*s%s", saved,
		    (int)(pos - prev), prev, replace) == -1)
			goto err;

		free(saved);
		prev = pos + search_len;
		saved = result;
	}

	if (asprintf(&result, "%s%s", saved, prev) == -1)
		goto err;
	free(saved);

	return result;
err:
	free(saved);
	return NULL;
}

void
reset_timer()
{
	struct itimerval exit_timer;

	bzero(&exit_timer, sizeof(exit_timer));
	exit_timer.it_value.tv_sec = timeout;
	if (setitimer(ITIMER_REAL, &exit_timer, NULL) == -1) {
		warn("setitimer");
		return;
	}

	if (debug_level)
		warnx("timer set to exit in %" PRIi64 " seconds",
			exit_timer.it_value.tv_sec);
}

void
read_cfg()
{
	char         buf[PATH_MAX + 32];
	char        *line;
	int          line_n = 0;
	FILE        *cfg;
	int          fd;
	struct stat  st;

	const char *p, *v;

	fd = open(cfg_path, O_RDONLY);
	if (fd == -1)
		err(1, "%s", cfg_path);

	if (fstat(fd, &st) == -1)
		err(1, "could not stat %s", cfg_path);

	if (permission_check) {
		if (st.st_uid != getuid())
			errx(1, "configuration file ownership is incorrect; "
			    "you should own it");

		if (st.st_mode & (S_IRWXO|S_IRWXG))
			errx(1, "configuration file permissions are incorrect; "
			    "only the owner should have access");
	}

	cfg = fdopen(fd, "r");
	if (cfg == NULL)
		err(1, "%s", cfg_path);

	while (fgets(buf, sizeof(buf), cfg)) {
		line_n++;
		line = buf;

		while (*line == ' ')
			line++;

		if (*line == '#' || *line == '\n' || *line == '\0')
			continue;

		p = strtok(line, ":");
		if (p == NULL) {
			warnx("invalid line in configuration: %d", line_n);
			continue;
		}

		v = strtok(NULL, "\n");
		if (v == NULL) {
			warnx("invalid line in configuration; no value: %d",
			    line_n);
			continue;
		}

		while (*v == ' ')
			v++;

		if (strcmp(p, "encrypt_cmd") == 0) {
			encrypt_cmd = strdup(v);
			if (encrypt_cmd == NULL)
				err(1, "could not load encrypt command");
		} else if (strcmp(p, "decrypt_cmd") == 0) {
			decrypt_cmd = strdup(v);
			if (decrypt_cmd == NULL)
				err(1, "could not load decrypt command");
		} else if (strcmp(p, "backup_cmd") == 0) {
			backup_cmd = strdup(v);
			if (backup_cmd == NULL)
				err(1, "could not load backup command");
		} else if (strcmp(p, "paste_cmd") == 0) {
			paste_cmd = strdup(v);
			if (paste_cmd == NULL)
				err(1, "could not load paste command");
		} else if (strcmp(p, "xtype_hotkey") == 0) {
			xtype_hotkey = strdup(v);
			if (xtype_hotkey == NULL)
				err(1, "could not load xtype_hotkey");
		} else if (strcmp(p, "xtype_esc") == 0) {
			xtype_esc = strdup(v);
			if (xtype_esc == NULL)
				err(1, "could not load xtype_esc");
		} else if (strcmp(p, "timeout") == 0) {
			if (atoi(v) < 0)
				warnx("invalid timeout specified");
			else
				timeout = atoi(v);
		} else if (strcmp(p, "mlock") == 0) {
			if (strcmp(v, "yes") == 0)
				no_mlock = 0;
			else if (strcmp(v, "no") == 0)
				no_mlock = 1;
			else
				warnx("no_mlock must be 'yes' or 'no'");
		} else if (strcmp(p, "max_value_length") == 0) {
			if (atoi(v) < 64)
				warnx("invalid max_value_length specified; "
				    "minimum is 64");
			else
				max_value_length = atoi(v);
		} else {
			warnx("unknown parameter: %s", p);
			continue;
		}

		if (debug_level)
			warnx("read_cfg: %s => %s", p, v);
	}

	if (encrypt_cmd == NULL)
		warnx("no encryption command defined; you will not be able to save");

	if (decrypt_cmd == NULL)
		errx(1, "no decryption command defined");

	if (paste_cmd == NULL)
		warnx("no paste command defined");

	fclose(cfg);
}

void
clear_db()
{
	if (db != NULL) {
		json_decref(db);
		db = NULL;
	}
}

int
load_db()
{
	int            cmd_fd;
	pid_t          child;
	int            status;
	json_error_t   error;
	char         **cmd_parts;
	int            decode_success = 0;

	if ((cmd_parts = str_split(decrypt_cmd)) == NULL)
		errx(1, "str_split");
	cmd_fd = safe_popen((char *const *)cmd_parts, 0, 1, &child);
	if (cmd_fd == -1)
		errx(1, "cannot decrypt");
	free(cmd_parts);

	db = json_load_callback(&load_json, &cmd_fd,
	    JSON_REJECT_DUPLICATES, &error);
	if (db == NULL) {
		if (timed_out)
			errx(1, "timeout while loading JSON");
	} else
		decode_success = 1;
again:
	if (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR && !timed_out)
			goto again;
		clear_db();
		err(1, "waitpid");
	}
	close(cmd_fd);

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0)
			warnx("decrypt command exited with code %d: %s",
			    WEXITSTATUS(status), decrypt_cmd);
		else if (!decode_success)
			warnx("JSON parse error (line %d): %s",
			    error.line, error.text);
	} else {
		warnx("decrypt command exited with signal %d: "
		    "command='%s'", WTERMSIG(status), decrypt_cmd);
	}
	return decode_success;
}

void
save_db()
{
	int     cmd_fd;
	char  **cmd_parts;
	int     status;
	pid_t   child;
	int     encode_failed = 0;

	/* We only do this once per run, even if we save multiple times */
	if (!db_backup_done && backup_cmd != NULL) {
		if (debug_level)
			warnx("backing up before saving");
		if ((cmd_parts = str_split(backup_cmd)) == NULL) {
			clear_db();
			errx(1, "str_split");
		}
		status = spawn((char *const *)cmd_parts);
		if (status == -1) {
			warnx("backup status unknown");
		} else if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != 0) {
				warnx("backup failed with status %d; "
				    "command='%s'", WEXITSTATUS(status),
				    backup_cmd);
			} else
				db_backup_done = 1;
		} else {
			warnx("backup failed with signal %d; "
			    "command='%s'", WTERMSIG(status), backup_cmd);
		}
		free(cmd_parts);
		if (!db_backup_done) {
			warnx("changes NOT saved");
			return;
		}
	}

	if (encrypt_cmd == NULL) {
		warnx("no encryption command defined; "
		    "you will not be able to save");
		return;
	}

	if (debug_level)
		warnx("saving: %s", encrypt_cmd);

	if ((cmd_parts = str_split(encrypt_cmd)) == NULL) {
		clear_db();
		errx(1, "str_split");
	}
	cmd_fd = safe_popen((char *const *)cmd_parts, 1, 1, &child);
	if (cmd_fd == -1) {
		warn("cannot encrypt");
		free(cmd_parts);
		return;
	}
	free(cmd_parts);

	if (json_dump_callback(db, &dump_json, &cmd_fd,
	    JSON_INDENT(2) | JSON_SORT_KEYS) == -1) {
		if (timed_out)
			warnx("timeout while writing JSON");
		else
			warnx("failed to write JSON output");
		encode_failed = 1;
	}
	close(cmd_fd);
again:
	if (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR && !timed_out)
			goto again;
		warn("waitpid");
		warnx("changes MAY NOT have been saved");
		return;
	}

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			warnx("encrypt command failed with code %d: %s",
			    WEXITSTATUS(status), encrypt_cmd);
			encode_failed = 1;
		}
	} else {
		warnx("encrypt command exited with signal %d: "
		    "command='%s'", WTERMSIG(status), encrypt_cmd);
		encode_failed = 1;
	}

	if (!encode_failed)
		warnx("changes were saved");
}

json_t *
get_secrets()
{
	json_t *secrets;

	secrets = json_object_get(db, "secrets");
	if (secrets == NULL)
		errx(1, "could not find \"secrets\" object; "
		    "invalid file format");
	return secrets;
}

int
cmp_key(const void *p1, const void *p2)
{
	return strcmp(*(const char **)p1, *(const char **)p2);
}

const char **
get_secret_names(const char *pattern)
{
	void        *iter;
	size_t       n_keys = 0;
	size_t       n_keys_max;
	const char **keys, **new_keys;
	const char  *name;

	n_keys_max = json_object_size(get_secrets()) * 2;

	/* Add an extra sizeof(char*) to make room for the last NULL */
	keys = locked_mem(n_keys_max * sizeof(char *) + sizeof(char *));
	if (keys == NULL)
		return NULL;

	for (iter = json_object_iter(get_secrets()); iter != NULL;
	    iter = json_object_iter_next(get_secrets(), iter)) {
		if (n_keys > n_keys_max) {
			new_keys = locked_mem(n_keys_max * 2 * sizeof(char *)
			    + sizeof(char *));
			if (new_keys == NULL)
				goto end;
			memcpy(new_keys, keys, n_keys * sizeof(char *));
			wipe_mem(keys);
			keys = new_keys;
			n_keys_max *= 2;
		}
		name = json_object_iter_key(iter);
		if (pattern) {
			if (strstr(name, pattern)) {
				keys[n_keys] = name;
				n_keys++;
			}
		} else {
			keys[n_keys] = name;
			n_keys++;
		}
	}

	keys[n_keys] = NULL;

	qsort(keys, n_keys, sizeof(char *), cmp_key);

	return keys;

end:
	wipe_mem(keys);
	return NULL;
}

void
list_secrets(const char *pattern)
{
	const char **key, **keys = get_secret_names(pattern);
	if (keys == NULL)
		return;
	for (key = keys; *key; key++) {
		printf("%s\n", *key);
	}
	wipe_mem(keys);
}

json_t *
find_secret(const char *key)
{
	return json_object_get(get_secrets(), key);
}

void
show_secret(json_t *obj, int hide_secret)
{
	json_t      *v;
	const char **f;

	if (obj == NULL) {
		printf("secret not found\n");
		return;
	}

	for (f = fields; *f; f++) {
		if (hide_secret && strcmp(*f, "secret") == 0)
			printf("%s: ******\n", *f);
		else if ((v = json_object_get(obj, *f)))
			printf("%s: %s\n", *f, json_string_value(v));
	}
}

/*
 * TODO: This is a bit flaky, sometimes one of the letters repeats, as
 *       if there is a race of some sort. For example, if a password is
 *       "Password", sometimes the result in the text box ends up being
 *       "PPssword". This never happens in a terminal, always in a browser
 *       window so far.
 */
int
x_err_handler(Display *xdpy, XErrorEvent *ev)
{
	char buf[1024];
	XGetErrorText(xdpy, ev->error_code, buf, sizeof(buf));
	warnx("X error: type=%d, error_code=%d: %s",
	    ev->type, ev->error_code, buf);
	return 0;
}

int
xevent_poll(Display *xdpy)
{
	struct pollfd pfd;

	pfd.fd = ConnectionNumber(xdpy);
	pfd.events = POLLIN;

	while (!XPending(xdpy)) {
		if (poll(&pfd, 1, -1) == -1) {
			if (errno == EINTR) {
				if (!timed_out)
					continue;
				return -1;
			}
			warn("poll");
			return -1;
		}
	}
	return 0;
}

void
xtype(json_t *obj)
{
	json_t      *v;
	const char **f;
	const char  *secret;
	wchar_t     *wc_secret = NULL, *wp;
	size_t       wc_secret_len;

	Display     *xdpy;
	const char  *d = getenv("DISPLAY");
	int          min_kc, max_kc, ks_per_kc;
	int          k, kc_i, ks_i, kc_empty;
	int          kc_scratch;
	int          kc_hot, kc_esc, ign_mod;
	KeySym      *keysyms, *ks = NULL;
	XEvent       ev;
	Window       root_w;
	XkbStateRec  kbstate;
	int          saved_kbgroup;

	if (obj == NULL) {
		printf("secret not found\n");
		return;
	}

	v = json_object_get(obj, "secret");
	if (v == NULL) {
		warnx("could not get secret");
		return;
	}

	if ((secret = json_string_value(v)) == NULL) {
		warnx("invalid JSON string for secret");
		return;
	}

	if ((xdpy = XOpenDisplay(d)) == NULL) {
		warnx("can't open display: %s\n", d);
		return;
	}

	XSetErrorHandler(x_err_handler);

	if (XStringToKeysym(xtype_hotkey) == 0) {
		warnx("invalid xtype_hotkey");
		goto exit_display;
	}
	if (XStringToKeysym(xtype_esc) == 0) {
		warnx("invalid xtype_esc");
		goto exit_display;
	}

	for (f = fields; *f; f++) {
		if (strcmp(*f, "secret") == 0)
			continue;
		if ((v = json_object_get(obj, *f)))
			printf("%s: %s\n", *f, json_string_value(v));
	}

	if (setlocale(LC_CTYPE, "") == NULL) {
		warn("setlocale");
		goto exit_display;
	}

	if ((wc_secret_len = mbstowcs(NULL, secret, 0)) == (size_t) -1) {
		warn("mbstowcs");
		goto exit_display;
	}

	wc_secret = locked_mem((wc_secret_len + 1) * sizeof(wchar_t));
	if (wc_secret == NULL) {
		warn("locked_mem");
		goto exit_display;
	}
	if (mbstowcs(wc_secret, secret, wc_secret_len + 1) == (size_t) -1) {
		warn("mbstowcs");
		goto exit_wcs;
	}

	printf("** Press %s to send keys, or %s to abort\n",
	    xtype_hotkey, xtype_esc);
	printf("** NOTE: this has not been well tested with non-ASCII "
	    "characters.\n");

	/*
	 * Grab secret-typing hotkey and ESC at the root.
	 */
	kc_hot = XKeysymToKeycode(xdpy, XStringToKeysym(xtype_hotkey));
	kc_esc = XKeysymToKeycode(xdpy, XStringToKeysym(xtype_esc));
	root_w = DefaultRootWindow(xdpy);
	ign_mod = Mod2Mask;

	XGrabKey(xdpy, kc_hot, 0, root_w, False,
	    GrabModeAsync, GrabModeAsync);
	XGrabKey(xdpy, kc_esc, 0, root_w, False,
	    GrabModeAsync, GrabModeAsync);

	XGrabKey(xdpy, kc_hot, ign_mod, root_w, False,
	    GrabModeAsync, GrabModeAsync);
	XGrabKey(xdpy, kc_esc, ign_mod, root_w, False,
	    GrabModeAsync, GrabModeAsync);

	/*
	 * Block until we either get XK_Escape or our secret-typing hotkey.
	 */
	XSelectInput(xdpy, root_w, KeyPressMask|KeyReleaseMask);
	for (;;) {
		if (xevent_poll(xdpy) == -1)
			goto exit_wcs;
		XNextEvent(xdpy, &ev);
		if (ev.type == KeyPress) {
			XUngrabKey(xdpy, kc_hot, 0, root_w);
			XUngrabKey(xdpy, kc_esc, 0, root_w);
			XUngrabKey(xdpy, kc_hot, ign_mod, root_w);
			XUngrabKey(xdpy, kc_esc, ign_mod, root_w);
			if (XLookupKeysym(&ev.xkey, 0) == XK_Escape)
				goto exit_wcs;
		}
		if (ev.type == KeyRelease)
			break;
	}
	XSelectInput(xdpy, root_w, 0);
	XSync(xdpy, False);

	/* Get a list of all keysyms for the current keyboard map */
	XDisplayKeycodes(xdpy, &min_kc, &max_kc);
	keysyms = XGetKeyboardMapping(xdpy, min_kc, max_kc - min_kc + 1,
	    &ks_per_kc);

	/*
	 * Find two unused keycode to use as scratch space; all keysyms should
	 * be zero for that keycode, otherwise we find another one.
	 */
	// TODO: try to find as many unused keycodes as the length of the
	// secret, this way we can perform a single keymap change. Some
	// applications process keymap changes in separate threads and
	// therefore might hit race conditions between keypress events and
	// keymap changes, resulting in the wrong keys being sent.
	// Use each variant in the keycode
	// Also dedup by character ...create our own keymap, sort of.
	for (kc_i = min_kc; kc_i < max_kc; kc_i++) {
		kc_empty = 1;
		for (ks_i = 0; ks_i < ks_per_kc; ks_i++) {
			k = (kc_i - min_kc) * ks_per_kc + ks_i;
			if (keysyms[k] != 0) {
				kc_empty = 0;
				break;
			}
		}
		if (kc_empty)
			break;
	}
	XFree(keysyms);

	if (kc_i == max_kc) {
		warnx("no empty keycode; cannot xtype");
		goto exit_wcs;
	}
	kc_scratch = kc_i;

	/* Create our fake keysyms for this keycode */
	ks = locked_mem(sizeof(KeySym) * ks_per_kc);
	if (ks == NULL) {
		warn("malloc");
		goto exit_wcs;
	}

	/*
	 * For each character in our secret, change the current keyboard
	 * mapping so that our scratch keycode gets all its keysyms set
	 * to that character. This way we don't need to bother about what
	 * modifiers are set.
	 */
	// TODO: we'll use modifiers so lock those as well
	for (wp = wc_secret; *wp != 0; wp++) {
		if (!iswprint(*wp) || !XKeysymToString(*wp)) {
			warnx("found non-printable character, "
			    "or XKeysymToString() failed");
			continue;
		}

		for (ks_i = 0; ks_i < ks_per_kc; ks_i++)
			ks[ks_i] = *wp;
		XChangeKeyboardMapping(xdpy, kc_scratch, ks_per_kc, ks, 1);
		XSync(xdpy, False);

		/* Press ... */
		XkbGetState(xdpy, XkbUseCoreKbd, &kbstate);
		saved_kbgroup = kbstate.group;
		XkbLockGroup(xdpy, XkbUseCoreKbd, 0);
		XTestFakeKeyEvent(xdpy, kc_scratch, True, CurrentTime);
		XkbLockGroup(xdpy, XkbUseCoreKbd, saved_kbgroup);
		XFlush(xdpy);
		usleep(30000);

		/* Release. */
		XkbGetState(xdpy, XkbUseCoreKbd, &kbstate);
		saved_kbgroup = kbstate.group;
		XkbLockGroup(xdpy, XkbUseCoreKbd, 0);
		XTestFakeKeyEvent(xdpy, kc_scratch, False, CurrentTime);
		XkbLockGroup(xdpy, XkbUseCoreKbd, saved_kbgroup);
		XFlush(xdpy);
		usleep(30000);

		for (ks_i = 0; ks_i < ks_per_kc; ks_i++)
			ks[ks_i] = 0;
		XChangeKeyboardMapping(xdpy, kc_scratch, ks_per_kc, ks, 1);
		XSync(xdpy, False);
	}
	wipe_mem(ks);
exit_wcs:
	wipe_mem(wc_secret);
exit_display:
	XCloseDisplay(xdpy);
}

void
paste(json_t *obj)
{
	json_t      *v;
	const char **f;
	int          cmd_fd;
	const char  *secret;
	ssize_t      w;
	int          status;
	char       **cmd_parts;
	pid_t        child;

	if (obj == NULL) {
		printf("secret not found\n");
		return;
	}

	if (paste_cmd == NULL) {
		warnx("no paste command defined");
		return;
	}

	for (f = fields; *f; f++) {
		if (strcmp(*f, "secret") == 0)
			continue;
		if ((v = json_object_get(obj, *f)))
			printf("%s: %s\n", *f, json_string_value(v));
	}

	if ((cmd_parts = str_split(paste_cmd)) == NULL)
		errx(1, "str_split");
	cmd_fd = safe_popen((char *const *)cmd_parts, 1, 1, &child);
	if (cmd_fd == -1) {
		warn("cannot paste");
		free(cmd_parts);
		return;
	}
	free(cmd_parts);

	v = json_object_get(obj, "secret");
	if (v == NULL) {
		warnx("could not get secret");
		close(cmd_fd);
		return;
	}
	if ((secret = json_string_value(v)) == NULL) {
		warnx("invalid JSON string for secret");
	} else {
		w = write(cmd_fd, secret, strlen(secret));
		if (w == -1) {
			warn("write");
		} else if (w < strlen(secret))
			warn("failed to write to paste command; "
			    "write count: %ld", w);
	}
	close(cmd_fd);
again:
	if (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR && !timed_out)
			goto again;
		warn("waitpid");
		return;
	}

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			warnx("paste command failed with code %d: '%s'",
			    WEXITSTATUS(status), paste_cmd);
		}
	} else {
		if (WTERMSIG(status) != 2)
			warnx("paste command exited with signal %d: "
			    "command='%s'", WTERMSIG(status), paste_cmd);
	}
}

int
confirm(const char *prompt, int dflt)
{
	unsigned char  c;
	struct termios saved_ts, new_ts;
	ssize_t        r;
	int            ret = 0;

	printf("%s ", prompt);
	fflush(stdout);

	if (tcgetattr(STDIN_FILENO, &saved_ts) == -1) {
		/*
		 * Auto-confirm if we're not on a TTY.
		 */
		if (errno == ENOTTY)
			return 1;
		warn("tcgetattr");
		return -1;
	}

	new_ts = saved_ts;
	new_ts.c_lflag &= ~ICANON;
	new_ts.c_cc[VMIN] = 1;
	new_ts.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &new_ts) == -1) {
		warn("tcsetattr");
		return -1;
	}
again:
	if ((r = read(0, &c, 1)) == -1) {
		if (errno == EINTR && !timed_out)
			goto again;
		warn("read");
		ret = -1;
		goto end;
	}
	if (r == 0) {
		warnx("read EOF");
		ret = -1;
		goto end;
	}

	switch (c) {
	case 'y':
	case 'Y':
		ret = 1;
		printf("\n");
		break;
	case 'n':
	case 'N':
		ret = 0;
		printf("\n");
		break;
	case '\n':
		ret = dflt;
		break;
	default:
		printf("\nPlease answer with 'y' or 'n': ");
		fflush(stdout);
		goto again;
	}
end:
	if (tcsetattr(STDIN_FILENO, TCSANOW, &saved_ts) == -1) {
		warn("tcsetattr");
		ret = -1;
	}

	if (ret != -1)
		reset_timer();
	return ret;
}

char *
read_field(const char *name, int echo)
{
	char           *input;
	struct termios  saved_ts, new_ts;
	ssize_t         r;

	printf("%s: ", name);
	fflush(stdout);

	if (!echo) {
		if (tcgetattr(STDIN_FILENO, &saved_ts) == -1) {
			warn("cannot get terminal settings");
			return NULL;
		}

		new_ts = saved_ts;
		new_ts.c_lflag &= ~ECHO;

		if (tcsetattr(0, TCSANOW, &new_ts) == -1) {
			warn("cannot set terminal settings");
			return NULL;
		}
	}

	input = locked_mem(max_value_length + 1);
	if (input == NULL) {
		warn("could not read field");
		goto end;
	}

	// TODO: eventually get rid of this by looping until we get to
	// a newline, then using a fixed buffer size like 4096, then realloc()
	// until we can fit it all. We'd still need a max_value_len, but it
	// could be much larger. And it paves the way to arbitrary secrets
	// like keys in base64.
again:
	r = read(0, input, max_value_length + 1);
	if (r == -1) {
		if (errno == EINTR && !timed_out)
			goto again;
		warn("read");
		wipe_mem(input);
		input = NULL;
		goto end;
	}
	if (r == 0) {
		warnx("read EOF");
		wipe_mem(input);
		input = NULL;
		goto end;
	}
	if ((r == max_value_length + 1) && input[r - 1] != '\n') {
		warnx("value too long");
		wipe_mem(input);
		input = NULL;
		goto end;
	}
	/* Squash the newline */
	if (input[r - 1] == '\n')
		input[r - 1] = '\0';
	else
		input[r] = '\0';
end:
	if (!echo) {
		if (tcsetattr(0, TCSANOW, &saved_ts) == -1) {
			warn("cannot reset terminal settings");
			wipe_mem(input);
			return NULL;
		}
		printf("\n");
	}

	return input;
}

int
add_secret(const char *key, int overwrite)
{
	json_t      *s, *old;
	char        *input, *input2;
	const char **f;

	if (find_secret(key) && !overwrite) {
		warnx("secret already exists");
		return -1;
	}

	if ((s = json_object()) == NULL) {
		warnx("json_object() failed");
		return -1;
	}

	if (overwrite) {
		old = json_object_get(get_secrets(), key);
		if (old == NULL) {
			warnx("couldn't get secret %s", key);
			goto fail;
		}
		if (json_object_update(s, old) == -1) {
			warnx("failed to update temporary JSON object");
			goto fail;
		}
	}

	for (f = fields; *f; f++) {
		if (overwrite) {
			printf("Change %s ? [y/N]", *f);
			switch (confirm("", 0)) {
			case 0:
				continue;
			case -1:
				goto fail;
			default:
				/* Proceed */
				break;
			}
		}
		if (strcmp(*f, "secret") == 0) {
			for (;;) {
				if ((input = read_field("secret", 0)) == NULL)
					goto fail;

				if ((input2 = read_field("confirm secret", 0))
				    == NULL) {
					wipe_mem(input);
					goto fail;
				}

				if (strcmp(input, input2) == 0) {
					wipe_mem(input2);
					break;
				}
				wipe_mem(input);
				wipe_mem(input2);
				printf("secrets don't match; try again\n");
			}
		} else {
			if ((input = read_field(*f, 1)) == NULL)
				goto fail;
		}

		if (json_object_set_new(s, *f, json_string(input)) == -1) {
			warnx("failed to add field %s to temporary "
			    "JSON object", *f);
			wipe_mem(input);
			goto fail;
		}

		wipe_mem(input);
		reset_timer();
	}

	if (overwrite) {
		printf("\nPlease confirm your changes:\n");
	} else {
		printf("\nPlease confirm if you wish to add this entry:\n");
		printf("\n=> %s\n", key);
	}

	show_secret(s, 1);

	switch (confirm("[Y/n]:", 1)) {
	case -1:
		goto fail;
	case 0:
		json_decref(s);
		return 0;
	default:
		/* Proceed */
		break;
	}

	if (overwrite) {
		if (json_object_update(old, s) == -1) {
			warnx("failed to overwrite current entry");
			goto fail;
		}
	} else {
		if (json_object_set_new(get_secrets(), key, s) == -1) {
			warnx("failed to add new entry");
			goto fail;
		}
	}

	if (overwrite)
		printf("Changed %s\n", key);
	else
		printf("Added %s\n", key);

	return 1;
fail:
	json_decref(s);
	return -1;
}

int
delete_secret(const char *key)
{
	if (key == NULL)
		return 0;

	switch (confirm("Are you sure [y/N]:", 0)) {
	case -1:
		return -1;
	case 0:
		return 0;
	default:
		/* Proceed */
		break;
	}

	if (json_object_del(get_secrets(), key) == -1) {
		warnx("failed to delete key");
		return 0;
	}

	printf("Deleted %s\n", key);
	return 1;
}

int
rename_secret(const char *old_key)
{
	json_t      *old, *new;
	char        *new_key;

	old = json_object_get(get_secrets(), old_key);
	if (old == NULL) {
		printf("couldn't get secret %s\n", old_key);
		return 0;
	}

	new_key = read_field("New secret name", 1);
	if (find_secret(new_key)) {
		printf("secret already exists\n");
		wipe_mem(new_key);
		return 0;
	}

	new = json_object();

	if (json_object_update(new, old) == -1) {
		warnx("failed to copy JSON object");
		wipe_mem(new_key);
		return 0;
	}

	if (json_object_set_new(get_secrets(), new_key, new) == -1) {
		warnx("failed to set new JSON object");
		wipe_mem(new_key);
		return 0;
	}

	if (json_object_del(get_secrets(), old_key) == -1) {
		warnx("failed to delete old JSON object");
	}

	printf("renamed '%s' to '%s'\n", old_key, new_key);
	wipe_mem(new_key);
	return 1;
}

void
sigalrm_handler(int sig)
{
	timed_out = 1;
	killpg(0, 15);
	if (in_readline) {
		rl_free_line_state();
		rl_cleanup_after_signal();
		write(STDERR_FILENO, "timed out\n", 10);
		restore_termios();
		_exit(1);
	}
}

void
sig_int(int unused)
{
	/*
	 * Child processes will reset the handler on execve(),
	 * so we have nothing more to do here.
	 */
	warnx("Interrupt sent to child processes");
}

char *
secrets_list_generator(const char *pattern, int state)
{
	char               *k;
	static const char **key, **keys;

	if (!state) {
		if (!load_db())
			return NULL;
		keys = get_secret_names(pattern);
		key = keys;
	}

	if (keys == NULL)
		goto end;

	while (*key) {
		k = strdup(*key++);
		if (k == NULL)
			goto end;
		return k;
	}
end:
	clear_db();
	wipe_mem(keys);
	return NULL;
}

char **
secrets_completion(const char *pattern, int start, int end)
{
	rl_attempted_completion_over = 1;
	return rl_completion_matches(pattern, secrets_list_generator);
}

int
main(int argc, char **argv)
{
	int               opt;
	char             *line = NULL;
	char             *token;
	int               quit = 0;
	char              prompt[sizeof(program_name) + 2];
	struct sigaction  act;
	struct rlimit     no_core = {0, 0};
	struct termios    ts;

	snprintf(prompt, sizeof(prompt), "%s> ", program_name);

	bzero(&act, sizeof(act));
	act.sa_handler = sig_int;
	if (sigaction(SIGINT, &act, NULL) == -1)
		err(1, "sigaction");

	/*
	 * We don't want the TERM signal to come in and terminate the
	 * program before we do any cleanup.
	 */
	bzero(&act, sizeof(act));
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGTERM, &act, NULL) == -1)
		err(1, "sigaction");

	while ((opt = getopt(argc, argv, "Xxdvhc:")) != -1) {
		switch (opt) {
		case 'h':
			print_help();
			exit(0);
		case 'd':
			debug_level++;
			break;
		case 'c':
			if (snprintf(cfg_path, sizeof(cfg_path), "%s", optarg)
			    >= sizeof(cfg_path))
				errx(1, "specified path is too long");
			break;
		case 'v':
			printf("%s version %s\n", PROGNAME, VERSION);
			exit(0);
		case 'x':
			permission_check = 0;
			break;
		case 'X':
			enable_core = 1;
			break;
		default:
			print_help();
			exit(1);
		}
	}

	if (debug_level)
		warnx("debug level set to %d", debug_level);

	if (*cfg_path == '\0') {
		if (getenv("XDG_CONFIG_HOME") != NULL &&
		    strcmp(getenv("XDG_CONFIG_HOME"), "") != 0) {
			if (snprintf(cfg_path, sizeof(cfg_path),
			    "%s/%s/%s.conf",
			    getenv("XDG_CONFIG_HOME"), program_name,
			    program_name) >= sizeof(cfg_path))
				errx(1, "XDG_CONFIG_HOME cfg path is too long");
		} else if (getenv("HOME") != NULL &&
		    strcmp(getenv("HOME"), "") != 0) {
			if (snprintf(cfg_path, sizeof(cfg_path),
			    "%s/.config/%s/%s.conf",
			    getenv("HOME"), program_name, program_name)
			    >= sizeof(cfg_path))
				errx(1, "HOME cfg path is too long");
		} else {
			errx(1, "neither HOME nor XDG_CONFIG_HOME is defined; "
			    "specify the config path manually");
		}
	}

	read_cfg();

	/*
	 * Save our terminal settings so we can restore at exit.
	 */
	if (tcgetattr(STDIN_FILENO, &saved_termios) == -1)
		err(1, "tcgetattr");

	ts = saved_termios;
	ts.c_iflag |= ICRNL;
	ts.c_oflag |= OPOST | ONLCR;
	ts.c_lflag |= ICANON | ECHO | ISIG | IEXTEN;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &ts) == -1)
		err(1, "tcsetattr");

	atexit(restore_termios);

	warnx("timeout set to %d seconds", timeout);

	if (!enable_core) {
		if (setrlimit(RLIMIT_CORE, &no_core) == -1)
			warn("could not disable core dumps; setrlimit");
	}

	umask(077);

	json_set_alloc_funcs(locked_mem, wipe_mem);

	rl_attempted_completion_function = secrets_completion;

	bzero(&act, sizeof(act));
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGTERM);
	sigaddset(&act.sa_mask, SIGALRM);
	act.sa_flags = 0;
	act.sa_handler = sigalrm_handler;
	if (sigaction(SIGALRM, &act, NULL) == -1)
		err(1, "sigaction");

	while (!quit && !timed_out) {
		reset_timer();
		in_readline = 1;
		line = readline(prompt);
		in_readline = 0;
		reset_timer();
		if (line == NULL)
			break;

		if (*line)
			add_history(line);

		token = strtok(line, " ");
		if (token == NULL)
			goto again;

		if (strcmp(token, "add") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: add [secret name]\n");
				goto again;
			}
			if (!load_db())
				goto again;
			if (add_secret(token, 0) == 1)
				save_db();
			clear_db();
		} else if (strcmp(token, "change") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: change [secret name]\n");
				goto again;
			}
			if (!load_db())
				goto again;
			if (add_secret(token, 1) == 1)
				save_db();
			clear_db();
		} else if (strcmp(token, "delete") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: delete [secret name]\n");
				goto again;
			}
			if (!load_db())
				goto again;
			if (delete_secret(token) == 1)
				save_db();
			clear_db();
		} else if (strcmp(token, "help") == 0) {
			printf("Help: add, change, delete, help, list, paste, "
			    "rename, save, quit, show, showall, xtype\n");
		} else if (strcmp(token, "list") == 0) {
			token = strtok(NULL, " ");
			if (!load_db())
				goto again;
			list_secrets(token);
			clear_db();
		} else if (strcmp(token, "xtype") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL || !load_db())
				goto again;
			xtype(find_secret(token));
			clear_db();
		} else if (strcmp(token, "paste") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL || !load_db())
				goto again;
			paste(find_secret(token));
			clear_db();
		} else if (strcmp(token, "rename") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: rename [secret name]\n");
				goto again;
			}
			if (!load_db())
				goto again;
			if (rename_secret(token))
				save_db();
			clear_db();
		} else if (strcmp(token, "save") == 0) {
			if (!load_db())
				goto again;
			save_db();
			clear_db();
		} else if (strcmp(token, "quit") == 0) {
			quit = 1;
		} else if (strcmp(token, "showall") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL || !load_db())
				goto again;
			show_secret(find_secret(token), 0);
			clear_db();
		} else if (strcmp(token, "show") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL || !load_db())
				goto again;
			show_secret(find_secret(token), 1);
			clear_db();
		} else {
			printf("unknown command\n");
		}
again:
		free(line);
	}
	clear_history();

	if (timed_out) {
		warnx("timeout reached");
		return 1;
	}

	printf("Bye.\n");
	return 0;
}
