using System;
using System.IO;
using System.Numerics;
using System.Globalization;

namespace ElectronicDigitalSignature
{
    class EllipticCurve
    {
        public BigInteger a;
        public BigInteger b;
        public BigInteger p;
        public BigInteger m;
        public BigInteger q;
    }

    class EllipticCurvePoint
    {
        public BigInteger x;
        public BigInteger y;
        public bool isZero;
    }

    class SignatureParameters
    {
        public EllipticCurve c;
        public EllipticCurvePoint P;
    }

    class SignatureKey
    {
        public BigInteger d;
    }

    class VerificationKey
    {
       public EllipticCurvePoint Q;
    }

    class EDS
    {        
        // this function uniformly generates a number from [minBound, maxBound)
        static BigInteger getRandomBigint(BigInteger minBound, BigInteger maxBound)
        {
            // we want to model multiplication by a number from [0; 1) interval
            BigInteger difference = maxBound - minBound;
            int length = difference.ToByteArray().Length;
            Random random = new Random();
            byte[] data = new byte[length];
            random.NextBytes(data);
            data[data.Length - 1] &= 0x7F; //force sign bit to positive
            BigInteger numerator = new BigInteger(data);
            BigInteger denominator = BigInteger.One << (data.Length * 8 - 1);
            // fraction numerator / denominator is from [0; 1)
            return minBound + (difference * numerator) / denominator;
        }

        // this function finds for given elements a and b representation gcd(a, b) = a * x + b * y
        static BigInteger ExtendedEuclideanAlgorithm(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {
            if (a == 0)
            {
                x = 0;
                y = 1;
                return b;
            }
            BigInteger x1, y1;
            BigInteger gcd = ExtendedEuclideanAlgorithm(b % a, a, out x1, out y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return gcd;
        }

        // this function finds inverse element for a in finite p-field
        static BigInteger InverseElement(BigInteger a, BigInteger p)
        {
            // p must be a prime number
            BigInteger x, y;
            BigInteger gcd = ExtendedEuclideanAlgorithm(a, p, out x, out y);
            return (x % p + p) % p;
        }

        // this function performs addition of two points on elliptic curve
        static EllipticCurvePoint AddEllipticCurvePoints(EllipticCurve c, EllipticCurvePoint p1, EllipticCurvePoint p2)
        {
            EllipticCurvePoint result = new EllipticCurvePoint();

            if (p1.isZero)
            {
                return p2;
            }

            if (p2.isZero)
            {
                return p1;
            }

            if (p1.x == p2.x && (p1.y + p2.y) % c.p == 0) 
            {
                result.isZero = true;
                return result;
            }

            BigInteger numerator, denominator;
            if (p1.x != p2.x)
            {
                numerator = (p2.y - p1.y + c.p) % c.p;
                denominator = (p2.x - p1.x + c.p) % c.p;
            }
            else
            {
                // (p1.x == p2.x && p1.y == p2.y && p1.y != 0)
                numerator = (3 * p1.x * p1.x + c.a) % c.p;
                denominator = (2 * p1.y) % c.p;
            }
            BigInteger lambda = (numerator * InverseElement(denominator, c.p)) % c.p;
            result.x = (lambda * lambda - p1.x - p2.x + 2 * c.p) % c.p;
            result.y = (lambda * (p1.x - result.x + c.p) - p1.y + c.p) % c.p;
            return result;
        }

        // this function performs quick multiplication of given point p on elliptic curve c by a given number k
        static EllipticCurvePoint MultiplyEllipticCurvePoints(EllipticCurve c, EllipticCurvePoint p, BigInteger k)
        {
            if (k == 1)
            {
                return p;
            }
            else if (k.IsEven)
            {
                EllipticCurvePoint q = MultiplyEllipticCurvePoints(c, p, k / 2);
                return AddEllipticCurvePoints(c, q, q);
            }
            else
            {
                EllipticCurvePoint q = MultiplyEllipticCurvePoints(c, p, k - 1);
                return AddEllipticCurvePoints(c, q, p);
            }
        }

        // this function creates a file with EDS for given document filename
        public static void CreateSignature(string filename, SignatureParameters signature, SignatureKey key)
        {
            BigInteger h = FileHash.CalculateHash(filename);
            //Console.WriteLine(h.ToString("x"));
            BigInteger e = h % signature.c.q;
            if (e == 0)
            {
                e = 1;
            }
            // this line below was used for testing according to the standard
            // e = BigInteger.Parse("20798893674476452017134061561508270130637142515379653289952617252661468872421");
          
            BigInteger r, s;
            while (true)
            {
                // this line below was used for testing according to the standard
                // BigInteger k = BigInteger.Parse("53854137677348463731403841147996619241504003434302020712960838528893196233395");
                BigInteger k = getRandomBigint(0, signature.c.q - 1) + 1;                
                // 0 < k < q
                r = MultiplyEllipticCurvePoints(signature.c, signature.P, k).x % signature.c.q;
                // this line below was used for testing according to the standard
                //Console.WriteLine(r);
                if (r == 0)
                {
                    continue;
                }
                s = (r * key.d + k * e) % signature.c.q;
                // this line below was used for testing according to the standard
                //Console.WriteLine(s);
                if (s != 0)
                {
                    break;
                }
            }
            BigInteger result = r * (BigInteger.One << 256) + s;

            // create an output file
            string signatureFile = filename + ".sg";
            StreamWriter fileStream = new StreamWriter(signatureFile);
            fileStream.Write(result.ToString("x").PadLeft(128, '0'));
            fileStream.Close();
        }

        // this function checks a file
        public static bool CheckSignature(string filename, SignatureParameters signature, VerificationKey key)
        {
            string signatureFile = filename + ".sg";
            StreamReader fileStream = new StreamReader(signatureFile);
            string signatureHex = fileStream.ReadLine();
            fileStream.Close();
            
            BigInteger r, s;
            r = BigInteger.DivRem(BigInteger.Parse(signatureHex, NumberStyles.AllowHexSpecifier), BigInteger.One << 256, out s);
            if (r <= 0 || r >= signature.c.q || s <= 0 || s >= signature.c.q)
            {
                throw new Exception("The signature file is invalid");
            }

            BigInteger h = FileHash.CalculateHash(filename);
            BigInteger e = h % signature.c.q;
            if (e == 0)
            {
                e = 1;
            }
            // this line below was used for testing according to the standard
            //e = BigInteger.Parse("20798893674476452017134061561508270130637142515379653289952617252661468872421");

            BigInteger v = InverseElement(e, signature.c.q);
            // this line below was used for testing according to the standard
            //Console.WriteLine(v);
            BigInteger z1 = (s * v) % signature.c.q;
            // this line below was used for testing according to the standard
            //Console.WriteLine(z1);
            BigInteger z2 = (-(r * v) % signature.c.q + signature.c.q) % signature.c.q;
            // this line below was used for testing according to the standard
            //Console.WriteLine(z2);
            EllipticCurvePoint C1 = MultiplyEllipticCurvePoints(signature.c, signature.P, z1);
            EllipticCurvePoint C2 = MultiplyEllipticCurvePoints(signature.c, key.Q, z2);
            EllipticCurvePoint C = AddEllipticCurvePoints(signature.c, C1, C2);
            // these lines below were used for testing according to the standard
            //Console.WriteLine(C.x);
            //Console.WriteLine(C.y);
            BigInteger R = C.x % signature.c.q;
            // this line below was used for testing according to the standard
            //Console.WriteLine(R);
            if (R == r)
            {
                return true;
            }
            else 
            {
                return false;
            }
        }
    }
}