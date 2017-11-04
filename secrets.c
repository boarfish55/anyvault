#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_tokener.h>

const char          program_name[] = PROGNAME;
const char         *version = VERSION;
int                 timeout = 300;
size_t              buf_size = (2 << 12);  /* 8k */
char                db_path[PATH_MAX + 1];
char                key_id[LINE_MAX + 1] = "";
struct json_object *db;
const char         *fields[] = {
	"notes",
	"url",
	"login",
	"secret",
	NULL
};


const char *encrypt_cmd = "/usr/bin/gpg --yes -se -r %s -o %s -";
const char *decrypt_cmd = "/usr/bin/gpg --decrypt %s";
const char *paste_cmd = "/usr/bin/xclip -l 1";

void
print_help()
{
	// TODO: add version flag, defined from the Makefile
	// TODO: better help
	printf("Usage: %s [-n] [-k <key id>] [-f <db path>] "
	    "[-t <timeout>] [-h]\n", program_name);
}

void
mem_err(size_t n)
{
	errx(1, "couldn't allocate %lu bytes; "
	    "check your ulimit for locked memory", n);
}

void
mem_warn(size_t n)
{
	warnx("couldn't allocate %lu bytes; "
	    "check your ulimit for locked memory", n);
}

void
wipe_mem(void *buf, size_t len)
{
	int      fd;
	ssize_t  r;
	size_t   pos;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		warn("could not open /dev/urandom");
		goto err;
	}

	for (pos = 0; pos >= len; pos += r) {
		r = read(fd, buf + pos, len - pos);
		if (r <= 0) {
			if (errno == EAGAIN)
				continue;
			warn("read");
			goto err;
		}
	}

	close(fd);
	free(buf);
	return;
err:
	warnx("cannot wipe uffer at address %p", buf);
	close(fd);
	free(buf);
}

void
load_db()
{
	FILE                   *cmd_fd;
	char                    cmd[PATH_MAX + 1];
	size_t                  r;
	size_t                  pos = 0;
        char                   *buf;
	enum json_tokener_error error;
	int                     st;

	if (access(db_path, F_OK) == -1) {
		warnx("database %s does not exist; will create", db_path);
		return;
	}

	if (access(db_path, R_OK) == -1)
		err(1, "cannot access database %s; "
		    "make sure it is readable", db_path);

	if (snprintf(cmd, sizeof(cmd), decrypt_cmd, db_path) >= sizeof(cmd))
		errx(1, "cannot decrypt; command too long");

	cmd_fd = popen(cmd, "r");
	if (cmd_fd == NULL)
		err(1, "cannot decrypt; popen");

	buf = malloc(buf_size);
	if (buf == NULL)
		mem_err(buf_size);

	for (;;) {
		r = fread(buf + pos, 1, buf_size - pos, cmd_fd);
		if (r == 0)
			break;

		pos += r;
		if (pos >= buf_size) {
			buf_size *= 2;
			buf = realloc(buf, buf_size);
			if (buf == NULL)
				mem_err(buf_size);
		}
	}

	if (ferror(cmd_fd))
		err(1, "fread");

	db = json_tokener_parse_verbose(buf, &error);
	if (db == NULL)
		errx(1, "error: %s\n", json_tokener_error_desc(error));
	wipe_mem(buf, buf_size);

	st = pclose(cmd_fd);
	switch (st) {
	case -1:
		err(1, "popen");
	case 0:
		break;
	default:
		errx(1, "decrypt command failed with code %d: %s",
		    st, cmd);
	}
}

void
save_db()
{
	FILE       *cmd_fd;
	char        cmd[PATH_MAX + 1];
	char        tmp_db_path[PATH_MAX + 1];
	int         tmp_fd;
	size_t      w;
	const char *buf;
	int         st;
	const char *tty;

	umask(0077);

	if (snprintf(tmp_db_path, sizeof(tmp_db_path), "%s.XXXXXX", db_path)
	    >= sizeof(tmp_db_path)) {
		warnx("cannot encrypt; db path too long");
		return;
	}

	tmp_fd = mkstemp(tmp_db_path);
	if (tmp_fd == -1) {
		warn("could not save database; mkstemp");
		return;
	}

	if (close(tmp_fd) == -1) {
		warn("could not save database; close");
		return;
	}

	if (snprintf(cmd, sizeof(cmd), encrypt_cmd, key_id, tmp_db_path)
	    >= sizeof(cmd)) {
		warnx("cannot encrypt; command too long");
		unlink(tmp_db_path);
		return;
	}

	// TODO: might need a better way to do this ...
	tty = ttyname(0);
	if (tty == NULL) {
		warn("ttyname");
		unlink(tmp_db_path);
		return;
	}
	if (setenv("GPG_TTY", tty, 1) == -1) {
		warn("could not set GPG_TTY");
		unlink(tmp_db_path);
		return;
	}

	cmd_fd = popen(cmd, "w");
	if (cmd_fd == NULL) {
		warn("cannot encrypt; popen");
		unlink(tmp_db_path);
		return;
	}

	buf = json_object_to_json_string_ext(db,
	    JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY);
	if (buf == NULL || *buf == '\0') {
		warn("could not prepare JSON output");
		unlink(tmp_db_path);
		pclose(cmd_fd);
		return;
	}

	w = fwrite(buf, 1, strlen(buf), cmd_fd);
	if (w < strlen(buf)) {
		warn("failed to write DB; write count: %lu", w);
		unlink(tmp_db_path);
		pclose(cmd_fd);
		return;
	}

	st = pclose(cmd_fd);
	switch (st) {
	case -1:
		warn("could not properly close file: %s", db_path);
		return;
	case 0:
		break;
	default:
		warnx("encrypt command failed with code %d: '%s'", st, cmd);
		return;
	}

	if (rename(tmp_db_path, db_path) == -1)
		warn("count not rename %s to %s", tmp_db_path, db_path);
}

struct json_object *
get_secrets()
{
	struct json_object *secrets;
	if (!json_object_object_get_ex(db, "secrets", &secrets))
		errx(1, "could not find \"secrets\" object; "
		    "invalid file format");
	return secrets;
}

int
cmp_key(const void *p1, const void *p2)
{
	return strcmp(*(const char **)p1, *(const char **)p2);
}

void
list_secrets(const char *pattern)
{
	struct json_object_iterator   i;
	struct json_object_iterator   il;
	size_t                        key;
	size_t                        n_keys;
	size_t                        n_keys_max = buf_size / 128;
	const char                  **keys;
	const char                   *name;

	keys = malloc(n_keys_max * sizeof(char *));
	if (keys == NULL) {
		mem_warn(n_keys_max * sizeof(char *));
		return;
	}

	for (n_keys = 0, i = json_object_iter_begin(get_secrets()),
	    il = json_object_iter_end(get_secrets());
	    !json_object_iter_equal(&i, &il); json_object_iter_next(&i)) {
		if (n_keys > n_keys_max) {
			keys = realloc(keys, n_keys_max * 2 * sizeof(char *));
			if (keys == NULL) {
				mem_warn(n_keys_max * 2 * sizeof(char *));
				goto end;
			}
			n_keys_max *= 2;
		}
		name = json_object_iter_peek_name(&i);
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

	qsort(keys, n_keys, sizeof(char *), cmp_key);

	for (key = 0; key < n_keys; key++) {
		printf("%s\n", keys[key]);
	}

end:
	wipe_mem(keys, n_keys_max * sizeof(char *));
}

struct json_object *
find_secret(const char *key)
{
	struct json_object  *s;

	if (!json_object_object_get_ex(get_secrets(), key, &s))
		return NULL;

	return s;
}

void
show_secret(struct json_object *obj, int hide_secret)
{
	struct json_object  *v;
	const char         **f;

	if (obj == NULL) {
		printf("secret not found\n");
		return;
	}

	for (f = fields; *f; f++) {
		if (hide_secret && strcmp(*f, "secret") == 0)
			printf("%s: ******\n", *f);
		else if (json_object_object_get_ex(obj, *f, &v))
			printf("%s: %s\n", *f, json_object_get_string(v));
	}
}

void
paste(struct json_object *obj)
{
	struct json_object  *v;
	FILE                *cmd_fd;
	const char          *secret;
	size_t               w;

	if (obj == NULL) {
		printf("secret not found\n");
		return;
	}

	cmd_fd = popen(paste_cmd, "w");
	if (cmd_fd == NULL) {
		warn("cannot paste; popen");
		return;
	}

	if (!json_object_object_get_ex(obj, "secret", &v)) {
		warnx("could not get secret");
		pclose(cmd_fd);
		return;
	}
	secret = json_object_get_string(v);

	w = fwrite(secret, 1, strlen(secret), cmd_fd);
	if (w < strlen(secret))
		warn("failed to write to paste command; write count: %lu", w);

	switch (pclose(cmd_fd)) {
	case -1:
		warn("paste command failed");
	case 0:
		break;
	default:
		warnx("paste command failed");
	}
}

char *
read_field(const char *name, int echo)
{
	char                *input;
	struct termios       saved_ts, new_ts;
	size_t               line_size = 0;

	printf("%s: ", name);
	fflush(stdout);

	if (!echo) {
		if (tcgetattr(0, &saved_ts) == -1)
			err(1, "cannot get terminal settings");

		new_ts = saved_ts;
		new_ts.c_lflag &= ~ECHO;

		if (tcsetattr(0, TCSANOW, &new_ts) == -1)
			err(1, "cannot set terminal settings");
	}

	if (getline(&input, &line_size, stdin) == -1)
		err(1, "getline");

	if (!echo) {
		if (tcsetattr(0, TCSANOW, &saved_ts) == -1)
			err(1, "cannot reset terminal settings");
		printf("\n");
	}

	input[strlen(input) - 1] = '\0';
	return input;
}

void
add_secret(const char *key, int overwrite)
{
	struct json_object  *s;
	char                *input, *input2;
	const char         **f;

	if (find_secret(key) && !overwrite) {
		printf("secret already exists\n");
		return;
	}

	if (!overwrite) {
		s = json_object_new_object();
	} else {
		if (!json_object_object_get_ex(get_secrets(), key, &s)) {
			printf("couldn't get secret %s\n", key);
			return;
		}
	}

	for (f = fields; *f; f++) {
		if (overwrite) {
			printf("Change %s ? [n]", *f);
			input = read_field("", 1);
			if (toupper(*input) != 'Y') {
				free(input);
				continue;
			}
		}
		if (strcmp(*f, "secret") == 0) {
			for (;;) {
				input = read_field("secret", 0);
				input2 = read_field("confirm secret", 0);
				if (strcmp(input, input2) == 0)
					break;
				printf("secrets don't match; try again\n");
			}
		} else {
			input = read_field(*f, 1);
		}

		if (overwrite)
			json_object_object_del(s, *f);

		json_object_object_add(s, *f, json_object_new_string(input));
		wipe_mem(input, strlen(input) + 1);
	}

	if (overwrite) {
		printf("\nPlease confirm your changes:\n");
	} else {
		printf("\nPlease confirm if you wish to add this entry:\n");
		printf("\n=> %s\n", key);
	}

	show_secret(s, 1);

	input = readline("[Y/n]: ");
	if (input == NULL)
		return;

	switch (*input) {
	case 'n':
	case 'N':
		return;
	case 'y':
	case 'Y':
	default:
		break;
	}

	if (!overwrite)
		json_object_object_add(get_secrets(), key, s);


	if (overwrite)
		printf("Changed %s\n", key);
	else
		printf("Added %s\n", key);
}

void
delete_secret(const char *key)
{
	char *input;

	if (key == NULL)
		return;

	input = readline("Are you sure [y/N]: ");
	if (input == NULL)
		return;

	switch (*input) {
	case 'y':
	case 'Y':
		break;
	default:
		return;
	}

	json_object_object_del(get_secrets(), key);
	printf("Deleted %s\n", key);
}

void
reset_timer()
{
	struct itimerval exit_timer;

	memset(&exit_timer, 0, sizeof(exit_timer));

	if (gettimeofday(&exit_timer.it_value, NULL) == -1)
		err(1, "gettimeofday");

	exit_timer.it_value.tv_sec += timeout;

	// Uh??
	if (setitimer(ITIMER_REAL, &exit_timer, NULL) == -1)
		err(1, "setitimer");
}

void
handle_segv(int unused)
{
	struct rusage ru;

	warn("segfault");
	warnx("Probably ran out of memory during JSON parsing");
	getrusage(RUSAGE_SELF, &ru);
	errx(1, "Current memory usage: %ld kb", ru.ru_maxrss);
}

int
main(int argc, char **argv)
{
	int   opt;
	char *line = NULL;
	char *token;
	int   quit = 0;
	int   modified = 0;
	int   no_mlock = 0;
	char  prompt[sizeof(program_name) + 2];

	struct sigaction act, oact;

	// TODO: check the returned length
	snprintf(prompt, sizeof(prompt), "%s> ", program_name);
	snprintf(db_path, sizeof(db_path), "%s/.%s.json.gpg",
	    getenv("HOME"), program_name);

	// TODO: implement timer (SIGALRM?)
	// TODO: better signal handling, show message. Block signals instead
	// of ignore? Ignore sigchild?


	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGINT, &act, &oact) == -1
	    || sigaction(SIGQUIT, &act, &oact) == -1) {
		err(1, "sigaction");
	}

	// Catch SIGSEGV as well until we find a better json lib that let's
	// us manage memory ourselves.
	act.sa_handler = &handle_segv;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGSEGV, &act, &oact) == -1) {
		err(1, "sigaction");
	}

	while ((opt = getopt(argc, argv, "hf:t:k:nv")) != -1) {
		switch (opt) {
		case 'n':
			no_mlock = 1;
			break;
		case 'k':
			strncpy(key_id, optarg, sizeof(key_id) - 1);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'h':
			print_help();
			exit(0);
		case 'f':
			strncpy(db_path, optarg, sizeof(db_path) - 1);
			break;
		case 'v':
			printf("%s version %s\n", PROGNAME, VERSION);
			exit(0);
		}
	}

	if (*key_id == '\0')
		errx(1, "key_id cannot be empty; use -k");

	reset_timer();

	if (!no_mlock && mlockall(MCL_FUTURE) == -1) {
		if (errno == ENOMEM) {
			warnx("Could not lock database in RAM; "
			    "contents might be swapped to disk");
			warnx("Check your ulimit for max locked memory");
		} else {
			err(1, "mlockall");
		}
	}

	load_db();

	while (!quit) {
		line = readline(prompt);
		reset_timer();
		if (line == NULL) {
			if (modified) {
				printf("Changes were made; either save or "
				    "use quit\n");
				continue;
			} else
				break;
		}

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
			add_secret(token, 0);
			modified = 1;
		} else if (strcmp(token, "change") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: change [secret name]\n");
				goto again;
			}
			add_secret(token, 1);
			modified = 1;
		} else if (strcmp(token, "delete") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: delete [secret name]\n");
				goto again;
			}
			delete_secret(token);
			modified = 1;
		} else if (strcmp(token, "help") == 0) {
			printf("Help: add, change, delete, help, list, paste, quit, save, show, showall\n");
		} else if (strcmp(token, "list") == 0) {
			token = strtok(NULL, " ");
			list_secrets(token);
		} else if (strcmp(token, "paste") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			paste(find_secret(token));
		} else if (strcmp(token, "quit") == 0) {
			if (modified) {
				token = read_field("Changes were made; "
				    "exit without saving? [y/N]", 1);
				if (toupper(*token) == 'Y')
					quit = 1;
				free(token);
			} else {
				quit = 1;
			}
		} else if (strcmp(token, "save") == 0) {
			save_db();
			modified = 0;
		} else if (strcmp(token, "showall") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			show_secret(find_secret(token), 0);
		} else if (strcmp(token, "show") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			show_secret(find_secret(token), 1);
		} else {
			printf("unknown command\n");
		}
again:
		wipe_mem(line, strlen(line) + 1);
	}

	// TODO: need to find a way to wipe_mem() here too
	json_object_put(db);

	printf("Bye.\n");
	return 0;
}
