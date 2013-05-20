using System;
using System.Collections.Generic;
using System.Text;
using Utility;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Soap;
using OpenSSL.Crypto;
using System.Collections;

namespace Wc3Sign
{
    class Program
    {
        const int SIGNATURE_OFFEST = 0x7E3196;
        static void Main(string[] args)
        {
            if (args.Length >= 1)
            {
                TryToPrase(args);
                //#DEBUG#
                //Console.Write("Press any key to continue...");
                //Console.ReadKey();
            }
            else
            {
                Console.WriteLine("example:");
                Console.WriteLine("-writedll [dllpath] -inkey [pempublickey]");
                return;
                while (true) 
                {
                    StandardInput();
                    Console.WriteLine("===================");
                }
            }
        }

        //TryToPrase(string[]) wrapper, converts string to string[]
        static void TryToPrase(string argsline)
        {
            TryToPrase(argsline.Split(' '));
        }

        static void TryToPrase(string[] args)
        {
            try
            {
                CmdArgs cmd = CmdLinePraser.CmdLinePrase(args);
                switch (cmd.FirstArgs)
                {
                    case "-writedll":
                        WriteDllWrapper(cmd);
                        break;
                    default:
                        Console.WriteLine("Unknow Arguments...");
                        break;
                }
            }
            catch
            {
                Console.WriteLine("sth went wrong");
            }
        }

        static void StandardInput()
        {
            Console.WriteLine("Write down your input:");
            Console.ReadLine();
            string input = "-writedll \"C:\\Users\\Administrator\\Desktop\\Game.dll\" -inkey \"C:\\Users\\Administrator\\Desktop\\Public RSA Keys\\Nirvana Map Private.pem\"";
            Console.WriteLine(input);
            TryToPrase(input);
        }


        /// <summary>
        /// working functions
        /// </summary>

        static void WriteDllWrapper(CmdArgs cmd)
        {
            string dllpath,pempath;
            try
            {
                dllpath = cmd.CommandArg.ArgPairs["writedll"];
                pempath = cmd.CommandArg.ArgPairs["inkey"];
                /*
                if (dllpath[0] == '"' && dllpath[dllpath.Length - 1] == '"')
                { dllpath = dllpath.Substring(1, dllpath.Length - 2); }
                if (pempath[0] == '"' && pempath[pempath.Length - 1] == '"')
                { pempath = pempath.Substring(1, pempath.Length - 2); }
                */
                if (!File.Exists(dllpath))
                { throw null; }
                else if (!File.Exists(pempath))
                {
                    Console.WriteLine(pempath);
                    throw null;
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Invaild Command or File Not Exist!");
                return;
            }
            //if normal, run the actual function.
            WriteDll(dllpath, pempath);
        }

        static void WriteDll(string dllpath, string pempath)
        {
            //Load public key
            StreamReader sr = new StreamReader(pempath);
            string keyaspem = sr.ReadToEnd();
            sr.Close();

            CryptoKey d;
            //Is private key
            if (keyaspem.IndexOf("-----BEGIN RSA PRIVATE KEY-----") == 0)
            {
                d = CryptoKey.FromPrivateKey(keyaspem, null);
            }
            //Is public key
            else if (keyaspem.IndexOf("-----BEGIN PUBLIC KEY-----") == 0)
            {
                d = CryptoKey.FromPublicKey(keyaspem, null);
            }
            else
            {
                Console.WriteLine("Key is not vaild.");
                return;
            }

            //Init openssl rsa component.
            RSA r = d.GetRSA();
            Console.WriteLine("Key File:");
            Console.WriteLine(pempath);
            Console.WriteLine();
            Console.WriteLine("Public Moludus: (reversed)");
            byte[] moludus=new byte[256];
            r.PublicModulus.ToBytes(moludus);
            Array.Reverse(moludus);
            Console.WriteLine(BitConverter.ToString(moludus));
            Console.WriteLine();
            Console.Write("Begin writing \"");
            Console.Write(dllpath);
            Console.Write("\" at ");
            Console.WriteLine("{0:x8}", SIGNATURE_OFFEST);  //hex output
            Console.WriteLine();

            //write game.dll
            FileStream fs = new FileStream(dllpath, FileMode.Open, FileAccess.ReadWrite);
            fs.Seek(SIGNATURE_OFFEST, SeekOrigin.Begin);
            fs.Write(moludus, 0, moludus.Length);
            fs.Close();
            Console.WriteLine("Writing successful");
            Console.WriteLine();
            Console.WriteLine("======================");
        }
    }
}
