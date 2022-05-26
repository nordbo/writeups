#include <sodium/randombytes.h>
#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <seccomp.h>

#define pr_err(fmt, ...) \
	do { \
		fprintf(stderr, "[-] " fmt, ## __VA_ARGS__); \
	} while (0)

#define MAX_SIZE 0x50
#define MAX_NOTES 10

struct note {
	uint8_t seed[randombytes_SEEDBYTES];
	uint8_t key[crypto_secretbox_KEYBYTES];
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	uint8_t *ciphertext;
	size_t size;
};

static struct note *flag;
static struct note *notes[MAX_NOTES];

static inline void menu(void)
{
	printf("1. encrypt\n");
	printf("2. print\n");
	printf("3. delete\n");
	printf("4. edit\n");
	printf("5. print flag\n");
	printf("6. exit\n");
}

static char *to_hex(const uint8_t *data, size_t len)
{
	char *hex;

	hex = calloc(1, (len * 2) + 1);
	if (!hex) {
		pr_err("calloc()\n");
		return NULL;
	}

	for (size_t i = 0; i < len; i++) {
		snprintf(&hex[i * 2], 3, "%02x", data[i]);
	}

	return hex;
}

static size_t get_num(const char *prompt)
{
	char buf[16];

	if (prompt)
		printf("%s", prompt);

	if (!fgets(buf, sizeof(buf), stdin)) {
		pr_err("fgets()\n");
		exit(EXIT_FAILURE);
	}

	return (size_t)strtoul(buf, NULL, 0);
}

static struct note *new_note(void)
{

	struct note *note;
	note = calloc(1, sizeof(*note));
	if (!note) {
		pr_err("calloc() note\n");
		return NULL;
	}
	randombytes_buf(note->seed, randombytes_SEEDBYTES);
	return note;
}

static struct note *get_free_note(size_t *idx)
{
	struct note *note;

	for (size_t i = 0; i < MAX_NOTES; i++) {
		if (notes[i])
			continue;
		note = new_note();
		notes[i] = note;
		*idx = i;
		return note;
	}

	return NULL;
}

static void remove_note(struct note *note)
{
	for (size_t i = 0; i < MAX_NOTES; i++) {
		if (note != notes[i])
			continue;

		notes[i] = NULL;
		break;
	}
}

static void delete_note(size_t idx)
{
	struct note *note;

	if (idx > MAX_NOTES) {
		pr_err("invalid index: %zu\n", idx);
		return;
	}
	note = notes[idx];
	if (!note) {
		pr_err("note not allocated!\n");
		return;
	}
	if (note->ciphertext) {
		sodium_memzero(note->ciphertext, note->size);
		free(note->ciphertext);
	}
	sodium_memzero(note, sizeof(*note));
	remove_note(note);
	free(note);
}

static void do_encrypt(struct note *note, void *data, size_t size)
{
	if (note->ciphertext && (size > note->size)) {
		sodium_memzero(note->ciphertext, note->size);
		free(note->ciphertext);
		note->ciphertext = NULL;
	}

	if (!note->ciphertext) {
		note->ciphertext = calloc(1, size + crypto_secretbox_MACBYTES);
		if (!note->ciphertext) {
			pr_err("calloc() ciphertext\n");
			return;
		}
	} else {
		sodium_memzero(note->ciphertext, note->size);
	}
	note->size = size;

	/* generate key and IV */
	randombytes_buf_deterministic(note->key,
				      sizeof(note->key) + sizeof(note->nonce),
				      note->seed);
	/* encrypt */
	crypto_secretbox_easy(note->ciphertext, (unsigned char *)data,
			      note->size, note->nonce, note->key);
	sodium_memzero(data, size);
}

static void encrypt(void)
{
	size_t size, idx;
	struct note *note;
	char data[MAX_SIZE] = { 0 };

	note = get_free_note(&idx);
	if (!note) {
		pr_err("no more room for notes!\n");
		return;
	}

	size = get_num("size: ");
	if (!size || size > MAX_SIZE) {
		pr_err("Invalid size: %zu\n", size);
		goto err;
	}

	printf("data: ");
	if (read(STDIN_FILENO, data, size) <= 0) {
		pr_err("failed to read data\n");
		goto err;
	}

	do_encrypt(note, data, size);
	printf("note %zu created successfully\n", idx);
	return;
err:
	delete_note(idx);
}

static void print(void)
{
	size_t idx;
	struct note *note;
	char *hex;

	idx = get_num("note: ");
	if (idx > MAX_NOTES) {
		pr_err("invalid index!\n");
		return;
	}

	note = notes[idx];
	if (!note) {
		pr_err("note not allocated!\n");
		return;
	}
	
	hex = to_hex(note->ciphertext, note->size + crypto_secretbox_MACBYTES);
	if (!hex)
		return;
	printf("%s\n", hex);
	free(hex);
}

static void delete(void)
{
	size_t idx;

	idx = get_num("note: ");
	delete_note(idx);
}

static size_t read_file(const char *filename, char *buf, size_t size)
{
	int fd;
	ssize_t ret;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		pr_err("failed to open file!\n");
		return 0;
	}

	ret = read(fd, buf, size);
	close(fd);
	if (ret <= 0) {
		pr_err("failed to read file!\n");
		return 0;
	}

	return (size_t)ret;
}

static void print_flag(void)
{
	char *hex;
	size_t len;
	char buf[1024] = { 0 };
	char *homedir;
	char flag_path[PATH_MAX] = { 0 };

	if (!flag) {
		flag = new_note();
		if (!flag) {
			pr_err("failed to allocate flag\n");
			exit(EXIT_FAILURE);
		}
	}

	homedir = getenv("HOME");
	if (!homedir) {
		pr_err("failed to get home directory\n");
		exit(EXIT_FAILURE);
	}

	snprintf(flag_path, sizeof(flag_path), "%s/flag.txt", homedir);
	len = read_file(flag_path, buf, sizeof(buf) - 1);
	if (!len)
		return;

	buf[strcspn(buf, "\n")] = '\0';
	len = strlen(buf);

	do_encrypt(flag, buf, len);
	hex = to_hex(flag->ciphertext, len + crypto_secretbox_MACBYTES);
	if (!hex)
		return;
	printf("%s\n", hex);
	free(hex);
}

static void edit(void)
{
	size_t idx, size;
	struct note *note;
	char buf[MAX_SIZE] = { 0 };

	idx = get_num("note: ");
	if (idx > MAX_NOTES) {
		pr_err("invalid index!\n");
		return;
	}

	note = notes[idx];
	if (!note) {
		pr_err("note not allocated!\n");
		return;
	}

	size = get_num("size: ");
	if (!size || size > MAX_SIZE) {
		pr_err("Invalid size: %zu\n", size);
		return;
	}

	printf("data: ");
	if (read(STDIN_FILENO, buf, size) <= 0) {
		pr_err("failed to read data\n");
		return;
	}

	do_encrypt(note, buf, size);
}

static void sandbox(void)
{
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (!ctx) {
		pr_err("seccomp_init() error\n");
		exit(EXIT_FAILURE);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);

	if (seccomp_load(ctx) < 0) {
		seccomp_release(ctx);
		pr_err("seccomp_load() error\n");
		exit(EXIT_FAILURE);
	}

	seccomp_release(ctx);
}

int main(void)
{
	int choice;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	alarm(60);

	sandbox();

	if (sodium_init()) {
		pr_err("failed to initialize sodium\n");
		exit(EXIT_FAILURE);
	}

	printf("Welcome to the securiest military grade note service\n");
	printf("- Protect your notes. Even from yourself!\n\n");
	for (;;) {
		menu();
		choice = get_num("> ");
		switch (choice) {
		case 1:
			encrypt();
			break;
		case 2:
			print();
			break;
		case 3:
			delete();
			break;
		case 4:
			edit();
			break;
		case 5:
			print_flag();
			break;
		case 6:
			exit(EXIT_SUCCESS);
		default:
			pr_err("invalid choice: %d\n", choice);
		}
	}

	return 0;
}
