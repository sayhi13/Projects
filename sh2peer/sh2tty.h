#include <termios.h>

bool is_canonical_tty = 1;

struct termios orig_tty;
struct termios non_canonical_tty;

void setup_non_canonical_tty() {
	tcgetattr(STDIN_FILENO, &orig_tty);

	non_canonical_tty = orig_tty;

	non_canonical_tty.c_lflag &= ~(ICANON | ECHO);
	non_canonical_tty.c_lflag &= ~ISIG;

	//non_canonical_tty.c_iflag &= ~(ICRNL | INLCR);

	non_canonical_tty.c_cc[VMIN] = 0;
	non_canonical_tty.c_cc[VTIME] = 1;

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &non_canonical_tty);

	is_canonical_tty = 0;
}

void restore_canonical_tty() {
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_tty);
	is_canonical_tty = 1;
}