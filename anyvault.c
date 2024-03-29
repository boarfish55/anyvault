/*
 *  anyvault -- a command-line password manager.
 *
 *  Copyright (C) 2019-2023 Pascal Lalonde <plalonde@overnet.ca>
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
size_t  max_value_length = 2048;
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

int         db_backup_done = 0;
json_t     *db = NULL;
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

// Used to track how much mlock'd memory we have. Used for reporting only.
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

	return p + sizeof(s);
}

/*
 * Opposite to locked_mem(), this overwrites to-be-freed memory with random
 * bytes, calls munlock() and finally frees the memory. The amount of bytes
 * is saved at (buf - sizeof(size_t)).
 */
void
wipe_mem(void *buf)
{
	int      fd;
	ssize_t  r;
	size_t   pos;
	size_t   len;
	void    *p;

	if (buf == NULL)
		return;

	p = buf - sizeof(len);
	len = *((size_t *)p);

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		warn("could not open /dev/urandom");
		warnx("cannot wipe buffer at address %p", buf);
		goto end;
	}

	for (pos = 0; pos < len; pos += r) {
		r = read(fd, buf + pos, len - pos);
		if (r <= 0) {
			if (errno == EAGAIN)
				continue;
			warn("cannot wipe buffer at address %p; read", buf);
			/* fallback to zeroes */
			explicit_bzero(buf, len);
			goto end;
		}
	}
end:
	if (fd != -1)
		close(fd);
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
	pid_t pid;
	int   null_fd;
	int   status;

	if ((pid = fork()) == -1) {
		warn("fork");
		return -1;
	} else if (pid == 0) {
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

		if (chdir("/") == -1) {
			warn("chdir");
			_exit(1);
		}

		if (execv(program[0], program) == -1) {
			warn("execv: %s", program[0]);
			_exit(1);
		}
	}
again:
	if (waitpid(pid, &status, 0) == -1) {
		if (errno == EINTR) {
			warn("waitpid");
			goto again;
		}
		err(1, "waitpid");
	}
	return status;
}

FILE *
safe_popen(char *const program[], const char *type, pid_t *pid)
{
	FILE *f;
	int   p_io[2];
	int   null_fd;

	if (pipe(p_io) == -1) {
		warn("pipe");
		return NULL;
	}

	fflush(stdin);

	if ((*pid = fork()) == -1) {
		warn("fork");
		close(p_io[0]);
		close(p_io[1]);
		return NULL;
	} else if (*pid == 0) {
		if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
			warn("open");
			_exit(1);
		}

		if (type[0] == 'r') {
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

		if (type[0] == 'w') {
			if (dup2(null_fd, STDOUT_FILENO) == -1) {
				warn("dup2");
				_exit(1);
			}
			if (dup2(p_io[0], STDIN_FILENO) == -1) {
				warn("dup2");
				_exit(1);
			}
			close(p_io[1]);
		}

		if (dup2(null_fd, STDERR_FILENO) == -1) {
			warn("dup2");
			_exit(1);
		}

		if (null_fd > 2)
			close(null_fd);

		if (chdir("/") == -1) {
			warn("chdir");
			_exit(1);
		}

		if (execv(program[0], program) == -1) {
			warn("execv: %s", program[0]);
			_exit(1);
		}
	}

	if (type[0] == 'r') {
		if ((f = fdopen(p_io[0], "r")) == NULL) {
			warn("fdopen");
			close(p_io[0]);
			close(p_io[1]);
			return NULL;
		}
		close(p_io[1]);
		if (type[1] == 'e' &&
		    fcntl(p_io[0], F_SETFD, FD_CLOEXEC) == -1) {
			warn("fcntl");
			fclose(f);
			return NULL;
		}
	} else if (type[0] == 'w') {
		if ((f = fdopen(p_io[1], "w")) == NULL) {
			warn("fdopen");
			close(p_io[0]);
			close(p_io[1]);
			return NULL;
		}
		close(p_io[0]);
		if (type[1] == 'e' &&
		    fcntl(p_io[1], F_SETFD, FD_CLOEXEC) == -1) {
			warn("fcntl");
			fclose(f);
			return NULL;
		}
	} else {
		errno = EINVAL;
		close(p_io[0]);
		close(p_io[1]);
		return NULL;
	}

	return f;
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
		} else if (strcmp(p, "xtype_esc") == 0) {
			xtype_esc = strdup(v);
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
			if (atoi(v) < 0)
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
load_db()
{
	FILE          *cmd_fd;
	pid_t          child;
	int            status;
	json_error_t   error;
	char          *iobuf;
	char         **cmd_parts;

	if ((cmd_parts = str_split(decrypt_cmd)) == NULL)
		errx(1, "str_split");
	cmd_fd = safe_popen((char *const *)cmd_parts, "r", &child);
	if (cmd_fd == NULL)
		errx(1, "cannot decrypt");
	free(cmd_parts);

	iobuf = locked_mem(BUFSIZ);
	if (iobuf == NULL)
		err(1, "load_db");
	setbuf(cmd_fd, iobuf);

	db = json_loadf(cmd_fd, JSON_REJECT_DUPLICATES, &error);
	if (db == NULL) {
		wipe_mem(iobuf);
		errx(1, "JSON parse error (line %d): %s\n",
		    error.line, error.text);
	}
again:
	if (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			warn("waitpid");
			goto again;
		}
		err(1, "waitpid");
	}
	fclose(cmd_fd);
	wipe_mem(iobuf);
	if (status != 0) {
		errx(1, "decrypt command failed with code %d: %s",
		    status, decrypt_cmd);
	}
}

void
clear_db()
{
	if (db != NULL) {
		json_decref(db);
		db = NULL;
	}
}

void
save_db()
{
	FILE   *cmd_fd;
	char  **cmd_parts;
	int     status;
	char   *iobuf;
	pid_t   child;
	int     encode_failed = 0;

	/* We only do this once per run, even if we save multiple times */
	if (!db_backup_done && backup_cmd != NULL) {
		if (debug_level)
			warnx("backing up before saving");
		if ((cmd_parts = str_split(backup_cmd)) == NULL)
			errx(1, "str_split");
		status = spawn((char *const *)cmd_parts);
		if (WIFEXITED(status)) {
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
	}

	if (encrypt_cmd == NULL) {
		warnx("no encryption command defined; "
		    "you will not be able to save");
		return;
	}

	if (debug_level)
		warnx("saving: %s", encrypt_cmd);

	iobuf = locked_mem(BUFSIZ);
	if (iobuf == NULL) {
		warn("save_db");
		return;
	}

	if ((cmd_parts = str_split(encrypt_cmd)) == NULL)
		errx(1, "str_split");
	cmd_fd = safe_popen((char *const *)cmd_parts, "w", &child);
	if (cmd_fd == NULL) {
		warn("cannot encrypt");
		free(cmd_parts);
		wipe_mem(iobuf);
		return;
	}
	free(cmd_parts);

	setbuf(cmd_fd, iobuf);

	if (json_dumpf(db, cmd_fd, JSON_INDENT(2) | JSON_SORT_KEYS) == -1) {
		warnx("could not prepare JSON output while saving");
		encode_failed = 1;
	}
	fclose(cmd_fd);
again:
	if (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			warn("waitpid");
			goto again;
		}
		err(1, "waitpid");
	}

	wipe_mem(iobuf);
	if (status != 0) {
		warnx("encrypt command failed with code %d: '%s'",
		    status, encrypt_cmd);
		encode_failed = 1;
	}

	if (encode_failed)
		return;

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
void
xtype(json_t *obj)
{
	json_t      *v;
	const char **f;
	const char  *secret;
	wchar_t     *wcs = NULL, *wp;
	size_t       wcs_l;

	Display     *xdpy;
	const char  *d = getenv("DISPLAY");
	int          min_kc, max_kc, ks_per_kc;
	int          k, kc_i, ks_i, kc_empty, kc_scratch;
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

	if ((wcs_l = mbstowcs(NULL, secret, 0)) == (size_t) -1) {
		warn("mbstowcs");
		goto exit_display;
	}

	wcs = locked_mem((wcs_l + 1) * sizeof(wchar_t));
	if (wcs == NULL) {
		warn("locked_mem");
		goto exit_display;
	}
	if (mbstowcs(wcs, secret, wcs_l + 1) == (size_t) -1) {
		warn("mbstowcs");
		goto exit_wcs;
	}

	printf("** Press %s to send keys, or %s to abort\n",
	    xtype_hotkey, xtype_esc);
	printf("** NOTE: this has not been well tested with non-ASCII "
	    "characters.\n");

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

	XSelectInput(xdpy, root_w, KeyPressMask|KeyReleaseMask);

	for (;;) {
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

	XDisplayKeycodes(xdpy, &min_kc, &max_kc);
	keysyms = XGetKeyboardMapping(xdpy, min_kc, max_kc - min_kc + 1,
	    &ks_per_kc);

	/* Find unused keycode to use as scratch space */
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

	ks = locked_mem(sizeof(KeySym) * ks_per_kc);
	if (ks == NULL) {
		warn("malloc");
		goto exit_wcs;
	}

	for (wp = wcs; *wp != 0; wp++) {
		if (!iswprint(*wp) || !XKeysymToString(*wp))
			continue;

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
		XSync(xdpy, False);
		usleep(20000);

		/* Release. */
		XkbGetState(xdpy, XkbUseCoreKbd, &kbstate);
		saved_kbgroup = kbstate.group;
		XkbLockGroup(xdpy, XkbUseCoreKbd, 0);
		XTestFakeKeyEvent(xdpy, kc_scratch, False, CurrentTime);
		XkbLockGroup(xdpy, XkbUseCoreKbd, saved_kbgroup);
		XSync(xdpy, False);
		usleep(20000);

		for (ks_i = 0; ks_i < ks_per_kc; ks_i++)
			ks[ks_i] = 0;
		XChangeKeyboardMapping(xdpy, kc_scratch, ks_per_kc, ks, 1);
		XSync(xdpy, False);
	}
	wipe_mem(ks);
exit_wcs:
	wipe_mem(wcs);
exit_display:
	XCloseDisplay(xdpy);
}

void
paste(json_t *obj)
{
	json_t      *v;
	const char **f;
	FILE        *cmd_fd;
	const char  *secret;
	size_t       w;
	char        *iobuf;
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

	iobuf = locked_mem(BUFSIZ);
	if (iobuf == NULL) {
		warnx("paste");
		return;
	}

	if ((cmd_parts = str_split(paste_cmd)) == NULL)
		errx(1, "str_split");
	cmd_fd = safe_popen((char *const *)cmd_parts, "w", &child);
	if (cmd_fd == NULL) {
		warn("cannot paste");
		free(cmd_parts);
		wipe_mem(iobuf);
		return;
	}
	free(cmd_parts);

	setbuf(cmd_fd, iobuf);

	v = json_object_get(obj, "secret");
	if (v == NULL) {
		warnx("could not get secret");
		fclose(cmd_fd);
		free(cmd_parts);
		wipe_mem(iobuf);
		return;
	}
	if ((secret = json_string_value(v)) == NULL) {
		warnx("invalid JSON string for secret");
	} else {
		w = fwrite(secret, 1, strlen(secret), cmd_fd);
		if (w < strlen(secret))
			warn("failed to write to paste command; "
			    "write count: %lu", w);
	}

	fclose(cmd_fd);
again:
	if (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			warn("waitpid");
			goto again;
		}
		err(1, "waitpid");
	}

	wipe_mem(iobuf);
	if (status != 0) {
		warnx("paste command failed with code %d: '%s'",
		    status, paste_cmd);
	}
}

int
confirm(const char *prompt, int dflt)
{
	int c;

	printf("%s ", prompt);
	fflush(stdout);

	for (;;) {
		c = getchar();

		if (c == '\n')
			return dflt;

		while (getchar() != '\n');

		switch (c) {
		case 'y':
		case 'Y':
			return 1;
		case 'n':
		case 'N':
			return 0;
		default:
			printf("Please answer with 'y' or 'n': ");
			fflush(stdout);
		}
	}
}

char *
read_field(const char *name, int echo)
{
	char           *input;
	struct termios  saved_ts, new_ts;

	printf("%s: ", name);
	fflush(stdout);

	if (!echo) {
		if (tcgetattr(0, &saved_ts) == -1) {
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

	input = locked_mem(max_value_length);
	if (input == NULL) {
		warn("could not read field");
		return NULL;
	}

	// TODO: eventually get rid of this by looping until we get to
	// a newline, then using a fixed buffer size like 4096, then realloc()
	// until we can fit it all. We'd still need a max_value_len, but it
	// could be much larger. And it paves the way to arbitrary secrets
	// like keys in base64.
	if (fgets(input, max_value_length + 1, stdin) == NULL) {
		warn("fgets");
		wipe_mem(input);
		return NULL;
	}

	if (!echo) {
		if (tcsetattr(0, TCSANOW, &saved_ts) == -1) {
			warn("cannot reset terminal settings");
			wipe_mem(input);
			return NULL;
		}
		printf("\n");
	}

	input[strlen(input) - 1] = '\0';
	return input;
}

int
add_secret(const char *key, int overwrite)
{
	json_t      *s, *old;
	char        *input, *input2;
	const char **f;

	if (find_secret(key) && !overwrite) {
		warnx("secret already exists\n");
		return 0;
	}

	s = json_object();
	if (overwrite) {
		old = json_object_get(get_secrets(), key);
		if (old == NULL) {
			warnx("couldn't get secret %s\n", key);
			return 0;
		}
		if (json_object_update(s, old) == -1) {
			warnx("failed to update temporary JSON object");
			return 0;
		}
	}

	for (f = fields; *f; f++) {
		if (overwrite) {
			printf("Change %s ? [y/N]", *f);
			if (!confirm("", 0))
				continue;
		}
		if (strcmp(*f, "secret") == 0) {
			for (;;) {
				if ((input = read_field("secret", 0)) == NULL)
					return 0;

				if ((input2 = read_field("confirm secret", 0))
				    == NULL) {
					wipe_mem(input);
					return 0;
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
				return 0;
		}

		if (json_object_set_new(s, *f, json_string(input)) == -1) {
			warnx("failed to add field %s to temporary "
			    "JSON object", *f);
			wipe_mem(input);
			return 0;
		}

		wipe_mem(input);
	}

	if (overwrite) {
		printf("\nPlease confirm your changes:\n");
	} else {
		printf("\nPlease confirm if you wish to add this entry:\n");
		printf("\n=> %s\n", key);
	}

	show_secret(s, 1);

	if (!confirm("[Y/n]:", 1))
		return 0;

	if (overwrite) {
		if (json_object_update(old, s) == -1) {
			warnx("failed to overwrite current entry");
			return 0;
		}
	} else {
		if (json_object_set_new(get_secrets(), key, s) == -1) {
			warnx("failed to add new entry");
			return 0;
		}
	}

	if (overwrite)
		printf("Changed %s\n", key);
	else
		printf("Added %s\n", key);

	return 1;
}

int
delete_secret(const char *key)
{
	if (key == NULL)
		return 0;

	if (!confirm("Are you sure [y/N]:", 0))
		return 0;

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
reset_timer()
{
	struct itimerval exit_timer;

	memset(&exit_timer, 0, sizeof(exit_timer));
	exit_timer.it_value.tv_sec = timeout;

	if (setitimer(ITIMER_REAL, &exit_timer, NULL) == -1) {
		warn("setitimer");
		return;
	}

	if (debug_level)
		warnx("timer set to exit in %lu seconds",
			exit_timer.it_value.tv_sec);
}

void
sig_handler(int sig)
{
	if (sig == SIGALRM)
		warnx("timeout reached");
	killpg(0, 15);
	clear_db();
	exit(0);
}

void
sig_int()
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
		load_db();
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
	int   opt;
	char *line = NULL;
	char *token;
	int   quit = 0;
	char  prompt[sizeof(program_name) + 2];

	struct sigaction act;

	struct rlimit no_core = {0, 0};

	snprintf(prompt, sizeof(prompt), "%s> ", program_name);

	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	sigaddset(&act.sa_mask, SIGTERM);
	sigaddset(&act.sa_mask, SIGALRM);
	act.sa_flags = 0;
	act.sa_handler = sig_handler;
	if (sigaction(SIGALRM, &act, NULL) == -1
	    || sigaction(SIGTERM, &act, NULL) == -1)
		err(1, "sigaction");

	act.sa_handler = sig_int;
	if (sigaction(SIGINT, &act, NULL) == -1)
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

	reset_timer();

	warnx("timeout set to %d seconds", timeout);

	if (!enable_core) {
		if (setrlimit(RLIMIT_CORE, &no_core) == -1)
			warn("could not disable core dumps; setrlimit");
	}

	json_set_alloc_funcs(locked_mem, wipe_mem);

	rl_attempted_completion_function = secrets_completion;

	while (!quit) {
		line = readline(prompt);
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
			load_db();
			if (add_secret(token, 0))
				save_db();
			clear_db();
		} else if (strcmp(token, "change") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: change [secret name]\n");
				goto again;
			}
			load_db();
			if (add_secret(token, 1))
				save_db();
			clear_db();
		} else if (strcmp(token, "delete") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: delete [secret name]\n");
				goto again;
			}
			load_db();
			if (delete_secret(token))
				save_db();
			clear_db();
		} else if (strcmp(token, "help") == 0) {
			printf("Help: add, change, delete, help, list, paste, "
			    "rename, save, quit, show, showall, xtype\n");
		} else if (strcmp(token, "list") == 0) {
			token = strtok(NULL, " ");
			load_db();
			list_secrets(token);
			clear_db();
		} else if (strcmp(token, "xtype") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			load_db();
			xtype(find_secret(token));
			clear_db();
		} else if (strcmp(token, "paste") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			load_db();
			paste(find_secret(token));
			clear_db();
		} else if (strcmp(token, "rename") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: rename [secret name]\n");
				goto again;
			}
			load_db();
			if (rename_secret(token))
				save_db();
			clear_db();
		} else if (strcmp(token, "save") == 0) {
			load_db();
			save_db();
			clear_db();
		} else if (strcmp(token, "quit") == 0) {
			quit = 1;
		} else if (strcmp(token, "showall") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			load_db();
			show_secret(find_secret(token), 0);
			clear_db();
		} else if (strcmp(token, "show") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			load_db();
			show_secret(find_secret(token), 1);
			clear_db();
		} else {
			printf("unknown command\n");
		}
again:
		free(line);
	}

	printf("Bye.\n");
	return 0;
}
