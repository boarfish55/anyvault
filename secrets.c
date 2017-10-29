#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_tokener.h>

size_t              buf_size = (2 << 12);  /* 8k */
const char         *prompt = "password1> ";
char                db_path[PATH_MAX + 1] = "~/.password1.gpg";
struct json_object *db;
const char         *fields[] = {
	"notes",
	"url",
	"login",
	"secret",
	NULL
};

const char *encrypt_cmd = "/usr/bin/gpg -c --cipher-algo AES-256 -o %s -";
const char *decrypt_cmd = "/usr/bin/gpg --decrypt %s";

void
print_help()
{
	printf("Usage: password1 [-f <db path>] [-h]\n");
}

void
mem_err(size_t n)
{
	errx(1, "couldn't allocate %lu bytes; "
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
	FILE                   *db_file;
	size_t                  r;
	size_t                  pos = 0;
        char                   *buf;
	enum json_tokener_error error;

	// TODO: decrypt command

	db_file = fopen(db_path, "r");
	if (db_file == NULL)
		err(1, "fopen: %s", db_path);

	buf = malloc(buf_size);
	if (buf == NULL)
		mem_err(buf_size);

	for (;;) {
		r = fread(buf + pos, 1, buf_size - pos, db_file);
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

	if (ferror(db_file))
		err(1, "fread");

	if (fclose(db_file) != 0)
		errx(1, "could not properly close file: %s", db_path);

	db = json_tokener_parse_verbose(buf, &error);
	if (db == NULL)
		errx(1, "error: %s\n", json_tokener_error_desc(error));
	wipe_mem(buf, buf_size);
}

void
save_db()
{
	FILE       *db_file;
	size_t      w;
	const char *buf;

	// TODO: encrypt command

	db_file = fopen(db_path, "w");
	if (db_file == NULL)
		warn("fopen: %s", db_path);

	buf = json_object_to_json_string_ext(db,
	    JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY);
	if (buf == NULL || *buf == '\0')
		warn("could not prepare JSON output");

	w = fwrite(buf, 1, strlen(buf), db_file);
	if (w < strlen(buf))
		warn("failed to write DB; write count: %lu", w);

	if (fclose(db_file) != 0)
		warn("could not properly close file: %s", db_path);
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
list_secrets()
{
	struct json_object_iterator   i;
	struct json_object_iterator   il;
	size_t                        key;
	size_t                        n_keys;
	size_t                        n_keys_max = buf_size / 128;
	const char                  **keys;

	keys = malloc(n_keys_max * sizeof(char *));
	if (keys == NULL)
		mem_err(n_keys_max * sizeof(char *));

	for (n_keys = 0, i = json_object_iter_begin(get_secrets()),
	    il = json_object_iter_end(get_secrets());
	    !json_object_iter_equal(&i, &il);
	    n_keys++, json_object_iter_next(&i)) {
		if (n_keys > n_keys_max) {
			n_keys_max *= 2;
			keys = realloc(keys, n_keys_max * sizeof(char *));
			if (keys == NULL)
				mem_err(n_keys_max * sizeof(char *));
		}
		keys[n_keys] = json_object_iter_peek_name(&i);
	}

	qsort(keys, n_keys, sizeof(char *), cmp_key);

	for (key = 0; key < n_keys; key++) {
		printf("%s\n", keys[key]);
	}

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

	if (obj == NULL) {
		printf("secret not found\n");
		return;
	}

	if (json_object_object_get_ex(obj, "secret", &v))
		printf("%s", json_object_get_string(v));

	// TODO ... send to 'xclip -l 1'
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

	s = json_object_new_object();

	for (f = fields; *f; f++) {
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

	if (overwrite)
		json_object_object_del(get_secrets(), key);

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

int
main(int argc, char **argv)
{
	int   opt;
	char *line = NULL;
	char *token;
	int   quit = 0;

	// TODO: signal handlers!!!

	// TODO: implement timer (SIGALRM?)

	while ((opt = getopt(argc, argv, "hf:")) != -1) {
		switch (opt) {
		case 'h':
			print_help();
			exit(0);
		case 'f':
			strncpy(db_path, optarg, sizeof(db_path) -1);
			break;
		}
	}

	if (mlockall(MCL_FUTURE) == -1) {
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
			add_secret(token, 0);
		} else if (strcmp(token, "change") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: change [secret name]\n");
				goto again;
			}
			add_secret(token, 1);
		} else if (strcmp(token, "delete") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL) {
				printf("Usage: delete [secret name]\n");
				goto again;
			}
			delete_secret(token);
		} else if (strcmp(token, "help") == 0) {
			printf("Help: add, change, delete, help, list, paste, quit, save, show, showall\n");
		} else if (strcmp(token, "list") == 0) {
			list_secrets();
		} else if (strcmp(token, "paste") == 0) {
			token = strtok(NULL, " ");
			if (token == NULL)
				goto again;
			paste(find_secret(token));
		} else if (strcmp(token, "quit") == 0) {
			quit = 1;
			// TODO: save reminder?
		} else if (strcmp(token, "save") == 0) {
			save_db();
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

	json_object_put(db);

	printf("Bye.\n");
	return 0;
}
