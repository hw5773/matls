#include "logger.h"

int main(){

	char *file = "example_file_name.txt";

	log_init(file);

	printLog(CLIENT_HANDSHAKE_START);
	printLog(CLIENT_HANDSHAKE_END);

	write_to_file();

	log_close();

	return 0;
}

