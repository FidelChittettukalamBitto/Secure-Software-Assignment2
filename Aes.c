#define KEY_SIZE 4
#define STATE_SIZE 4
#define SBOX_SIZE 16
#define MAX_ROUNDS 11
#define SBOX_LOOKUP(lookup_box, num) lookup_box[(num) >> 4][(num) & 0x0F];


// Global state
uint8_t static key[KEY_SIZE][KEY_SIZE];
uint8_t static state[STATE_SIZE][STATE_SIZE];
uint8_t static orig_msg[STATE_SIZE][STATE_SIZE];
uint8_t static sbox[SBOX_SIZE][SBOX_SIZE];
uint8_t static inv_sbox[SBOX_SIZE][SBOX_SIZE];
uint8_t static sub_keys [MAX_ROUNDS][KEY_SIZE][KEY_SIZE];
int initialize_called;
