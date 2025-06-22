#include "MD5Hash.h"

namespace API {
	inline MD5Hash::uint4 MD5Hash::F(uint4 x, uint4 y, uint4 z) { return x & y | ~x & z; }

	inline MD5Hash::uint4 MD5Hash::G(uint4 x, uint4 y, uint4 z) { return x & z | y & ~z; }

	inline MD5Hash::uint4 MD5Hash::H(uint4 x, uint4 y, uint4 z) { return x ^ y ^ z; }

	inline MD5Hash::uint4 MD5Hash::I(uint4 x, uint4 y, uint4 z) { return y ^ (x | ~z); }

	inline MD5Hash::uint4 MD5Hash::Rotate_left(uint4 x, INT n) { return (x << n) | (x >> (32 - n)); }

	inline VOID MD5Hash::FF(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) { a = Rotate_left(a + F(b, c, d) + x + ac, s) + b; }

	inline VOID MD5Hash::GG(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) { a = Rotate_left(a + G(b, c, d) + x + ac, s) + b; }

	inline VOID MD5Hash::HH(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) { a = Rotate_left(a + H(b, c, d) + x + ac, s) + b; }

	inline VOID MD5Hash::II(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) { a = Rotate_left(a + I(b, c, d) + x + ac, s) + b; }

	MD5Hash::MD5Hash() { Init(); }

	MD5Hash::MD5Hash(CONST std::string& Text) {
		Init();
		Update(Text.c_str(), Text.length());
		Finalize();
	}

	VOID MD5Hash::Init() {
		Finalized = FALSE;
		Count[0] = NULL;
		Count[1] = NULL;
		State[0] = 0x67452301;
		State[1] = 0xefcdab89;
		State[2] = 0x98badcfe;
		State[3] = 0x10325476;
	}

	VOID MD5Hash::Decode(uint4 Output[], CONST uint1 Input[], size_type Length) {
		for (uint4 i = 0, j = 0; j < Length; i++, j += 4)
			Output[i] = ((uint4)Input[j]) | (((uint4)Input[j + 1]) << 8) |
			(((uint4)Input[j + 2]) << 16) | (((uint4)Input[j + 3]) << 24);
	}

	VOID MD5Hash::Encode(uint1 Output[], CONST uint4 Input[], size_type Length) {
		for (size_type x = 0, j = 0; j < Length; x++, j += 4) {
			Output[j] = Input[x] & 0xff;
			Output[j + 1] = (Input[x] >> 8) & 0xFF;
			Output[j + 2] = (Input[x] >> 16) & 0xFF;
			Output[j + 3] = (Input[x] >> 24) & 0xFF;
		}
	}

	VOID MD5Hash::Transform(CONST uint1 Block[Blocksize]) {
		uint4 a = State[0], b = State[1], c = State[2], d = State[3], x[16];
		Decode(x, Block, Blocksize);

		FF(a, b, c, d, x[0], S11, 0xd76aa478);
		FF(d, a, b, c, x[1], S12, 0xe8c7b756);
		FF(c, d, a, b, x[2], S13, 0x242070db);
		FF(b, c, d, a, x[3], S14, 0xc1bdceee);
		FF(a, b, c, d, x[4], S11, 0xf57c0faf);
		FF(d, a, b, c, x[5], S12, 0x4787c62a);
		FF(c, d, a, b, x[6], S13, 0xa8304613);
		FF(b, c, d, a, x[7], S14, 0xfd469501);
		FF(a, b, c, d, x[8], S11, 0x698098d8);
		FF(d, a, b, c, x[9], S12, 0x8b44f7af);
		FF(c, d, a, b, x[10], S13, 0xffff5bb1);
		FF(b, c, d, a, x[11], S14, 0x895cd7be);
		FF(a, b, c, d, x[12], S11, 0x6b901122);
		FF(d, a, b, c, x[13], S12, 0xfd987193);
		FF(c, d, a, b, x[14], S13, 0xa679438e);
		FF(b, c, d, a, x[15], S14, 0x49b40821);

		GG(a, b, c, d, x[1], S21, 0xf61e2562);
		GG(d, a, b, c, x[6], S22, 0xc040b340);
		GG(c, d, a, b, x[11], S23, 0x265e5a51);
		GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
		GG(a, b, c, d, x[5], S21, 0xd62f105d);
		GG(d, a, b, c, x[10], S22, 0x2441453);
		GG(c, d, a, b, x[15], S23, 0xd8a1e681);
		GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
		GG(a, b, c, d, x[9], S21, 0x21e1cde6);
		GG(d, a, b, c, x[14], S22, 0xc33707d6);
		GG(c, d, a, b, x[3], S23, 0xf4d50d87);
		GG(b, c, d, a, x[8], S24, 0x455a14ed);
		GG(a, b, c, d, x[13], S21, 0xa9e3e905);
		GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
		GG(c, d, a, b, x[7], S23, 0x676f02d9);
		GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

		HH(a, b, c, d, x[5], S31, 0xfffa3942);
		HH(d, a, b, c, x[8], S32, 0x8771f681);
		HH(c, d, a, b, x[11], S33, 0x6d9d6122);
		HH(b, c, d, a, x[14], S34, 0xfde5380c);
		HH(a, b, c, d, x[1], S31, 0xa4beea44);
		HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
		HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
		HH(b, c, d, a, x[10], S34, 0xbebfbc70);
		HH(a, b, c, d, x[13], S31, 0x289b7ec6);
		HH(d, a, b, c, x[0], S32, 0xeaa127fa);
		HH(c, d, a, b, x[3], S33, 0xd4ef3085);
		HH(b, c, d, a, x[6], S34, 0x4881d05);
		HH(a, b, c, d, x[9], S31, 0xd9d4d039);
		HH(d, a, b, c, x[12], S32, 0xe6db99e5);
		HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
		HH(b, c, d, a, x[2], S34, 0xc4ac5665);

		II(a, b, c, d, x[0], S41, 0xf4292244);
		II(d, a, b, c, x[7], S42, 0x432aff97);
		II(c, d, a, b, x[14], S43, 0xab9423a7);
		II(b, c, d, a, x[5], S44, 0xfc93a039);
		II(a, b, c, d, x[12], S41, 0x655b59c3);
		II(d, a, b, c, x[3], S42, 0x8f0ccc92);
		II(c, d, a, b, x[10], S43, 0xffeff47d);
		II(b, c, d, a, x[1], S44, 0x85845dd1);
		II(a, b, c, d, x[8], S41, 0x6fa87e4f);
		II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
		II(c, d, a, b, x[6], S43, 0xa3014314);
		II(b, c, d, a, x[13], S44, 0x4e0811a1);
		II(a, b, c, d, x[4], S41, 0xf7537e82);
		II(d, a, b, c, x[11], S42, 0xbd3af235);
		II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
		II(b, c, d, a, x[9], S44, 0xeb86d391);

		State[0] += a;
		State[1] += b;
		State[2] += c;
		State[3] += d;

		ZeroMemory(x, sizeof(x));
	}

	VOID MD5Hash::Update(CONST BYTE Input[], size_type Length) {
		size_type Index = Count[0] / 8 % Blocksize;
		if ((Count[0] += (Length << 3)) < (Length << 3)) { Count[1]++; }
		Count[1] += (Length >> 29);
		size_type Firstpart = 64 - Index;
		size_type I;

		if (Length >= Firstpart) {
			memcpy(&Buffer[Index], Input, Firstpart);
			Transform(Buffer);
			for (I = Firstpart; I + Blocksize <= Length; I += Blocksize) { Transform(&Input[I]); }
			Index = NULL;
		}
		else I = NULL;
		memcpy(&Buffer[Index], &Input[I], Length - I);
	}

	VOID MD5Hash::Update(CONST CHAR Input[], size_type Length) {
		Update((CONST BYTE*)Input, Length);
	}

	MD5Hash& MD5Hash::Finalize() {
		static BYTE Padding[64] = {
			0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		};
		if (!Finalized) {
			BYTE Bits[8];
			Encode(Bits, Count, 8);
			size_type Index = Count[0] / 8 % 64;
			size_type PadLen = (Index < 56) ? (56 - Index) : (120 - Index);
			Update(Padding, PadLen);
			Update(Bits, 8);
			Encode(Digest, State, 16);
			ZeroMemory(Buffer, sizeof(Buffer));
			ZeroMemory(Count, sizeof(Count));
			Finalized = TRUE;
		}
		return *this;
	}

	std::string MD5Hash::HexDigest() CONST {
		if (!Finalized) { return ""; }
		CHAR Buffer[32 + 1];
		for (size_type FL = 0; FL < 16; FL++) {
			sprintf_s(Buffer + FL * 2, sizeof(Buffer), "%02x", Digest[FL]);
		}
		Buffer[32] = NULL;
		return std::string(Buffer);
	}

	std::ostream& operator<<(std::ostream& Out, MD5Hash MD5) {
		return Out << MD5.HexDigest();
	}

	std::string MD5(CONST std::string Input) {
		MD5Hash MD5 = MD5Hash(Input);
		return MD5.HexDigest();
	}

	VOID MD5HASH(std::string file_name, char p[])
	{
		DWORD dwStatus = 0;
		BOOL bResult = FALSE;
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		HANDLE hFile = NULL;
		BYTE rgbFile[BUFSIZE];
		DWORD cbRead = 0;
		BYTE rgbHash[MD5LEN];
		DWORD cbHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";

		wchar_t wtext[MAX_PATH];
		mbstowcs(wtext, file_name.c_str(), strlen(file_name.c_str()) + 1);
		LPCWSTR filename = wtext;

		// Logic to check usage goes here.

		hFile = CreateFileW(filename,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_SEQUENTIAL_SCAN,
			NULL);

		if (INVALID_HANDLE_VALUE == hFile)
		{
			dwStatus = GetLastError();
			printf("Error opening file %s\nError: %d\n", file_name.c_str(), dwStatus);
			sprintf(p, "%s", "-1");
			return;
		}

		// Get handle to the crypto provider
		if (!CryptAcquireContext(&hProv,
			NULL,
			NULL,
			PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT))
		{
			dwStatus = GetLastError();
			printf("CryptAcquireContext failed: %d\n", dwStatus);
			CloseHandle(hFile);
			sprintf(p, "%s", "-1");
			return;
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			dwStatus = GetLastError();
			printf("CryptAcquireContext failed: %d\n", dwStatus);
			CloseHandle(hFile);
			CryptReleaseContext(hProv, 0);
			sprintf(p, "%s", "-1");
			return;
		}

		while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
			&cbRead, NULL))
		{
			if (0 == cbRead)
			{
				break;
			}

			if (!CryptHashData(hHash, rgbFile, cbRead, 0))
			{
				dwStatus = GetLastError();
				printf("CryptHashData failed: %d\n", dwStatus);
				CryptReleaseContext(hProv, 0);
				CryptDestroyHash(hHash);
				CloseHandle(hFile);
				sprintf(p, "%s", "-1");
				return;
			}
		}

		if (!bResult)
		{
			dwStatus = GetLastError();
			printf("ReadFile failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			sprintf(p, "%s", "-1");
			return;
		}
		cbHash = MD5LEN;
		if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
		{
			int x = 0;
			for (DWORD i = 0; i < cbHash; i++)
			{
				p[x++] = rgbDigits[rgbHash[i] >> 4];
				p[x++] = rgbDigits[rgbHash[i] & 0xf];
			}
			p[32] = '\0';
		}
		else
		{
			dwStatus = GetLastError();
			printf("CryptGetHashParam failed: %d\n", dwStatus);
			sprintf(p, "%s", "-1");
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		CloseHandle(hFile);
		Sleep(100);
	}
}