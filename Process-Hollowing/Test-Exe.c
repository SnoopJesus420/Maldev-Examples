#include <Windows.h>
#include <stdio.h>

int main() {
	int number = 0;
	
	fprintf(stdout, "[i] This is output from the injected PE!!\n");
	fflush(stdout);
	fprintf(stdout, "\t [+] Congrats! It Worked!\n");
	fflush(stdout);
	fprintf(stdout, "[+] Press 1 to close... ");
	fflush(stdout);
	scanf_s("%d", number);

	if (number == 1) {
		return -1;
	}

	return 0;
}
