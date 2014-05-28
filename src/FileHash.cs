using System;
using System.Numerics;
using System.IO;

namespace ElectronicDigitalSignature
{
    class Keccak
    {
        // modified SHA-3 (Keccak) algorithm 256-bit
        const int r = 1088;
        const int c = 512;        
        const int numberOfRounds = 24;

        // rotation constants
        ulong [] RC = 
        {
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808A,
            0x8000000080008000,
            0x000000000000808B,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008A,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000A,
            0x000000008000808B,
            0x800000000000008B,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800A,
            0x800000008000000A,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008,
        };

        // the rotation offsets
        int [,] Rotations =
        {
            { 0, 36,  3, 41, 18},
            { 1, 44, 10, 45,  2},
            {62,  6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39,  8, 14},
        };

        // bits of ulong x are shifted left by n bits
        ulong rotate(ulong x, int n)
        {
            int shift = n % 64;
            return ((x << n) | (x >> (64 - n)));
        }

        // main Keccak state modification operations
        ulong [,] Round(ulong [,] A, ulong RC)
        {
            ulong [] C = new ulong[5];
            ulong [,] B = new ulong[5, 5];
            for (int x = 0; x < 5; ++x)
            {
                C[x] = A[x, 0] ^ A[x, 1] ^ A[x, 2] ^ A[x, 3] ^ A[x, 4];
            }

            for (int x = 0; x < 5; ++x)
            {
                ulong D = C[(x + 4) % 5] ^ rotate(C[(x + 1) % 5], 1);
                for (int y = 0; y < 5; ++y) 
                {
                    A[x, y] ^= D;
                    B[y, (2 * x + 3 * y) % 5] = rotate(A[x, y], Rotations[x, y]);
                }
            }

            for (int x = 0; x < 5; ++x)
            {
                for (int y = 0; y < 5; ++y)
                {
                    A[x, y] = B[x, y] ^ ((~B[(x + 1) % 5, y]) & B[(x + 2) % 5, y]);
                }
            }
            A[0, 0] ^= RC;
            return A;
        }

        // rounds of state modification
        ulong [,] KeccakFun(ulong [,] A)
        {
            for (int i = 0; i < numberOfRounds; ++i )
            {
                A = Round(A, RC[i]);                
            }
            return A;
        }

        // get hash for message N
        public byte[] KeccakHash(byte[] N)
        {
            ulong[,] S = new ulong[5, 5];
            byte[] M = new byte[N.Length + 1];
            int oldLength = M.Length;
            N.CopyTo(M, 0);
            M[oldLength - 1] = 0x01;

            byte[] P;
            if (oldLength % (r / 8) != 0) 
            {
                // padding
                int newLength = oldLength - (oldLength % (r / 8)) + (r / 8);
                P = new byte[newLength];                
                M.CopyTo(P, 0);                            
                P[newLength - 1] ^= 0x80;
            } 
            else 
            {
                P = new byte[oldLength];
                M.CopyTo(P, 0);
            }

            // absorb
            int nBytesInBlock = (r / 8); // 136
            int nBlocks = P.Length / nBytesInBlock;
            int usedNumbersInBlock = r / 64;  // 17                        
            for (int i = 0; i < nBlocks; ++i)
            {
                for (int x = 0; x < 5; ++x)
                {
                    for (int y = 0; y < 5; ++y)
                    {
                        if (x * 5 + y < usedNumbersInBlock) {
                            byte[] tmp = new byte[8];                            
                            
                            Array.Copy(P, i * nBytesInBlock + (x * 5 + y) * 8, tmp, 0, 8);
                            Array.Reverse(tmp, 0, tmp.Length);
                            ulong c = BitConverter.ToUInt64(tmp, 0);
                            S[x, y] ^= c;
                            S = KeccakFun(S);
                        }
                    }
                }                                          
            }        

            // squeeze
            int neededLength = 4; // 256 bit = 4 * 64
            int currLength = 0;
            byte[] h = new byte[neededLength * 8];
            while (true)
            {
                for (int x = 0; x < 5; ++x)
                {
                    for (int y = 0; y < 5; ++y)
                    {
                        if (neededLength == currLength)
                        {
                            return h;
                        }
                        if (x * 5 + y < usedNumbersInBlock)
                        {
                            byte[] tmp = BitConverter.GetBytes(S[x, y]);
                            Array.Reverse(tmp, 0, tmp.Length);                          
                            tmp.CopyTo(h, currLength * 8);
                            ++currLength;
                            S = KeccakFun(S);
                        }
                    }
                }
            }
        }
    }
        
    class FileHash
    {        
        // get BigInteger hash value for file filename to use in EDS algorithms
        public static BigInteger CalculateHash(string filename)
        {
            Keccak KeccakHash = new Keccak();
            FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read);
            byte[] data = File.ReadAllBytes(filename);
            byte[] hash = KeccakHash.KeccakHash(data);
            hash[hash.Length - 1] &= 0x7F; // the number must be positive                        

            BigInteger result = new BigInteger(hash);
            return result;
        }
    }
}