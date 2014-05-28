using System;
using NDesk.Options;
using System.Numerics;

namespace ElectronicDigitalSignature
{
    class Program
    {
        // main function
        static void Main(string[] args)
        {
            // all the values are taken from the text of the standard
            SignatureParameters Signature = new SignatureParameters();
            Signature.c = new EllipticCurve();
            Signature.P = new EllipticCurvePoint();

            Signature.c.p = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564821041");
            Signature.c.a = BigInteger.Parse("7");
            Signature.c.b = BigInteger.Parse("43308876546767276905765904595650931995942111794451039583252968842033849580414");
            Signature.c.m = BigInteger.Parse("57896044618658097711785492504343953927082934583725450622380973592137631069619");
            Signature.c.q = BigInteger.Parse("57896044618658097711785492504343953927082934583725450622380973592137631069619");
            Signature.P.x = BigInteger.Parse("2");
            Signature.P.y = BigInteger.Parse("4018974056539037503335449422937059775635739389905545080690979365213431566280");
            Signature.P.isZero = false;

            SignatureKey SignatureKey = new SignatureKey();
            SignatureKey.d = BigInteger.Parse("55441196065363246126355624130324183196576709222340016572108097750006097525544");

            VerificationKey VerificationKey = new VerificationKey();
            VerificationKey.Q = new EllipticCurvePoint();
            VerificationKey.Q.x = BigInteger.Parse("57520216126176808443631405023338071176630104906313632182896741342206604859403");
            VerificationKey.Q.y = BigInteger.Parse("17614944419213781543809391949654080031942662045363639260709847859438286763994");
            VerificationKey.Q.isZero = false;

            bool showHelp = false;
            var p = new OptionSet() {
                { "s|sign=", "the {FILENAME} to sign", 
                    v => {
                        EDS.CreateSignature(v, Signature, SignatureKey);
                        Console.WriteLine("The signature is succesfully created!");
                    }
                },
                { "c|check=", "the {FILENAME} to be verified", 
                    v => {
                        
                        if (EDS.CheckSignature(v, Signature, VerificationKey))
                        {
                            Console.WriteLine("The signature is valid!");
                        }
                        else
                        {
                            Console.WriteLine("The signature is NOT valid!");
                        }

                    }
                },
                { "h|help", "show this message and exit", 
                    v => showHelp = true},
            };

            try 
            {
                p.Parse(args);
            }
            catch(Exception e) 
            {
                Console.Write("eds: ");
                Console.WriteLine(e.Message);
                Console.WriteLine ("Try 'eds --help' for more information.");
            }

            if (showHelp)
            {
                ShowHelp(p);
                return;
            }           
        }

        // this function shows help to user in the console
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: eds [OPTIONS]");
            Console.WriteLine("Create or verify an electronic digital signature (EDS) for a file.");
            Console.WriteLine("To verify the file its signature file (.sg-file) must be positioned in the same folder.");
            Console.WriteLine("The algoritm of EDS is GOST R 34.10-2001");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }
    }
}
