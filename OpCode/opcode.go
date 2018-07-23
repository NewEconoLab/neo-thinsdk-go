package OpCode

const (
	// Constants
	PUSH0    		byte = 0x00 // An empty array of bytes is pushed onto the stack.
	PUSHF     		byte = PUSH0
	PUSHBYTES1  	byte = 0x01 // 0x01-0x4B The next opcode bytes is data to be pushed onto the stack
	PUSHBYTES75 	byte = 0x4B
	PUSHDATA1   	byte = 0x4C // The next byte contains the number of bytes to be pushed onto the stack.
	PUSHDATA2   	byte = 0x4D // The next two bytes contain the number of bytes to be pushed onto the stack.
	PUSHDATA4   	byte = 0x4E // The next four bytes contain the number of bytes to be pushed onto the stack.
	PUSHM1      	byte = 0x4F // The number -1 is pushed onto the stack.
	PUSH1       	byte = 0x51 // The number 1 is pushed onto the stack.
	PUSHT       	byte = PUSH1
	PUSH2       	byte = 0x52 // The number 2 is pushed onto the stack.
	PUSH3       	byte = 0x53 // The number 3 is pushed onto the stack.
	PUSH4       	byte = 0x54 // The number 4 is pushed onto the stack.
	PUSH5       	byte = 0x55 // The number 5 is pushed onto the stack.
	PUSH6       	byte = 0x56 // The number 6 is pushed onto the stack.
	PUSH7       	byte = 0x57 // The number 7 is pushed onto the stack.
	PUSH8       	byte = 0x58 // The number 8 is pushed onto the stack.
	PUSH9       	byte = 0x59 // The number 9 is pushed onto the stack.
	PUSH10      	byte = 0x5A // The number 10 is pushed onto the stack.
	PUSH11      	byte = 0x5B // The number 11 is pushed onto the stack.
	PUSH12      	byte = 0x5C // The number 12 is pushed onto the stack.
	PUSH13      	byte = 0x5D // The number 13 is pushed onto the stack.
	PUSH14      	byte = 0x5E // The number 14 is pushed onto the stack.
	PUSH15      	byte = 0x5F // The number 15 is pushed onto the stack.
	PUSH16      	byte = 0x60 // The number 16 is pushed onto the stack.

	// Flow control
	NOP      		byte = 0x61 // Does nothing.
	JMP      		byte = 0x62
	JMPIF    		byte = 0x63
	JMPIFNOT 		byte = 0x64
	CALL     		byte = 0x65
	RET      		byte = 0x66
	APPCALL  		byte = 0x67
	SYSCALL  		byte = 0x68
	TAILCALL 		byte = 0x69

	// Stack
	DUPFROMALTSTACK 	byte = 0x6A
	TOALTSTACK      	byte = 0x6B // Puts the input onto the top of the alt stack. Removes it from the main stack.
	FROMALTSTACK    	byte = 0x6C // Puts the input onto the top of the main stack. Removes it from the alt stack.
	XDROP           	byte = 0x6D
	XSWAP           	byte = 0x72
	XTUCK           	byte = 0x73
	DEPTH           	byte = 0x74 // Puts the number of stack items onto the stack.
	DROP            	byte = 0x75 // Removes the top stack item.
	DUP             	byte = 0x76 // Duplicates the top stack item.
	NIP             	byte = 0x77 // Removes the second-to-top stack item.
	OVER            	byte = 0x78 // Copies the second-to-top stack item to the top.
	PICK            	byte = 0x79 // The item n back in the stack is copied to the top.
	ROLL            	byte = 0x7A // The item n back in the stack is moved to the top.
	ROT             	byte = 0x7B // The top three items on the stack are rotated to the left.
	SWAP            	byte = 0x7C // The top two items on the stack are swapped.
	TUCK            	byte = 0x7D // The item at the top of the stack is copied and inserted before the second-to-top item.

	// Splice
	CAT    		byte = 0x7E // Concatenates two strings.
	SUBSTR 	byte = 0x7F // Returns a section of a string.
	LEFT   		byte = 0x80 // Keeps only characters left of the specified point in a string.
	RIGHT  		byte = 0x81 // Keeps only characters right of the specified point in a string.
	SIZE   		byte = 0x82 // Returns the length of the input string.

	// Bitwise logic
	INVERT 	byte = 0x83 // Flips all of the bits in the input.
	AND    		byte = 0x84 // Boolean and between each bit in the inputs.
	OR     		byte = 0x85 // Boolean or between each bit in the inputs.
	XOR    		byte = 0x86 // Boolean exclusive or between each bit in the inputs.
	EQUAL  		byte = 0x87 // Returns 1 if the inputs are exactly equal, 0 otherwise.
	//OP_EQUALVERIFY = 0x88, // Same as OP_EQUAL, but runs OP_VERIFY afterward.
	//OP_RESERVED1 = 0x89, // Transaction is invalid unless occuring in an unexecuted OP_IF branch
	//OP_RESERVED2 = 0x8A, // Transaction is invalid unless occuring in an unexecuted OP_IF branch

	// Arithmetic
	// Note: Arithmetic inputs are limited to signed 32-bit integers, but may overflow their output.
	INC         	byte = 0x8B // 1 is added to the input.
	DEC         	byte = 0x8C // 1 is subtracted from the input.
	SIGN        	byte = 0x8D
	NEGATE      	byte = 0x8F // The sign of the input is flipped.
	ABS         	byte = 0x90 // The input is made positive.
	NOT         	byte = 0x91 // If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
	NZ          	byte = 0x92 // Returns 0 if the input is 0. 1 otherwise.
	ADD         	byte = 0x93 // a is added to b.
	SUB         	byte = 0x94 // b is subtracted from a.
	MUL         	byte = 0x95 // a is multiplied by b.
	DIV         	byte = 0x96 // a is divided by b.
	MOD         	byte = 0x97 // Returns the remainder after dividing a by b.
	SHL         	byte = 0x98 // Shifts a left b bits, preserving sign.
	SHR         	byte = 0x99 // Shifts a right b bits, preserving sign.
	BOOLAND     	byte = 0x9A // If both a and b are not 0, the output is 1. Otherwise 0.
	BOOLOR      	byte = 0x9B // If a or b is not 0, the output is 1. Otherwise 0.
	NUMEQUAL    	byte = 0x9C // Returns 1 if the numbers are equal, 0 otherwise.
	NUMNOTEQUAL 	byte = 0x9E // Returns 1 if the numbers are not equal, 0 otherwise.
	LT          	byte = 0x9F // Returns 1 if a is less than b, 0 otherwise.
	GT          	byte = 0xA0 // Returns 1 if a is greater than b, 0 otherwise.
	LTE         	byte = 0xA1 // Returns 1 if a is less than or equal to b, 0 otherwise.
	GTE         	byte = 0xA2 // Returns 1 if a is greater than or equal to b, 0 otherwise.
	MIN         	byte = 0xA3 // Returns the smaller of a and b.
	MAX         	byte = 0xA4 // Returns the larger of a and b.
	WITHIN      	byte = 0xA5 // Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.

	// Crypto
	//RIPEMD160 = 0xA6, // The input is hashed using RIPEMD-160.
	SHA1    		byte = 0xA7 // The input is hashed using SHA-1.
	SHA256  		byte = 0xA8 // The input is hashed using SHA-256.
	HASH160 		byte = 0xA9
	HASH256 		byte = 0xAA
	//因为这个hash函数可能仅仅是csharp 编译时专用的
	CSHARPSTRHASH32 	byte = 0xAB
	//这个是JAVA专用的
	JAVAHASH32 		byte = 0xAD

	CHECKSIG      		byte = 0xAC
	CHECKMULTISIG 	byte = 0xAE

	// Array
	ARRAYSIZE 		byte = 0xC0
	PACK      		byte = 0xC1
	UNPACK    		byte = 0xC2
	PICKITEM  		byte = 0xC3
	SETITEM   		byte = 0xC4
	NEWARRAY  		byte = 0xC5 //用作引用類型
	NEWSTRUCT 		byte = 0xC6 //用作值類型

	SWITCH 		byte = 0xD0

	// Exceptions
	THROW      		byte = 0xF0
	THROWIFNOT 	byte = 0xF1
)
