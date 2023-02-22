#pragma once

typedef struct _PS_PROTECTION
{
	UCHAR Type : 3;
	UCHAR Audit : 1;
	UCHAR Signer : 4;
} PS_PROTECTION, *PPS_PROTECTION;

typedef struct _PROCESS_PROTECTION_INFO
{
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
} PROCESS_PROTECTION_INFO, *PPROCESS_PROTECTION_INFO;

typedef struct _PROCESS_PRIVILEGES
{
	UCHAR Present[8];
	UCHAR Enabled[8];
	UCHAR EnabledByDefault[8];
} PROCESS_PRIVILEGES, *PPROCESS_PRIVILEGES;

const ULONG PROCESS_PRIVILEGE_OFFSET[] =
{
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x40, // REDSTONE_5
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x40 // 21H2
};

const ULONG PROCESS_PROTECTION_OFFSET[] =
{
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x6c8, // REDSTONE_5
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x878 // Windows_21H2
};


const UCHAR OPCODE_CALL = 0xE8;
const UCHAR OPCODE_JMP = 0xE9;
const UCHAR OPCODE_LEA = 0x4C;
const UCHAR OPCODE_LEA_R2 = 0x8D;
const UCHAR OPCODE_LEA_R3 = 0x2D;

const UCHAR PSP_OPCODE[] =
{
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // REDSTONE_5
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // placeholder
	OPCODE_CALL, // placeholder
	OPCODE_CALL // 21H2
};

const UCHAR OPCODE_LEA_R1_THREAD_NOTIFY = 0x48;
const UCHAR OPCODE_LEA_R2_THREAD_NOTIFY = 0x8D;
const UCHAR OPCODE_LEA_R3_THREAD_NOTIFY = 0x0D;

const ULONG PROCESS_NOTIFY_LEA[] =
{
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0xe8, // REDSTONE_5
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0x00, // placeholder
	0xE8 // placeholder
};
