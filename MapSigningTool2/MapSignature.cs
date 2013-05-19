using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
//using System.Security.Cryptography;
using System.Windows.Forms;
using OpenSSL.Crypto;

namespace MapSigningTool
{
    class MapSignature
    {
        public static byte[] SIGNATURE_HEADER = Encoding.ASCII.GetBytes("NGIS");

        public static int IndexOfBytes(byte[] arrayToSearchThrough, byte[] patternToFind)
        {
            if (patternToFind.Length > arrayToSearchThrough.Length)
                return -1;
            for (int i = 0; i < arrayToSearchThrough.Length - patternToFind.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < patternToFind.Length; j++)
                {
                    if (arrayToSearchThrough[i + j] != patternToFind[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return i;
                }
            }
            return -1;
        }

        //=====================================================
        // Calculate map hash(reversed) and dump map signature(if any)
        // - return the starting pos of signature block(-1 if none)
        //=====================================================
        public static long MapGetSignatureInfo(string mappath, ref byte[] maphash, ref byte[] mapsignature)
        {
            long signature_pos = -1;
            string mapname = Path.GetFileName(mappath);
            byte[] mapnamebytes = Encoding.ASCII.GetBytes(mapname.ToUpper());   //upper filename

            System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create();
            Stream input = File.OpenRead(mappath);
            byte[] buffer_old = new byte[200];
            byte[] buffer = new byte[200];  //read 200 bytes each time
            int bytesRead, bytesRead_old;
            bool findblockheader = false;

            //Mpq is a vaild map
            bytesRead = input.Read(buffer, 0, buffer.Length);   //read mpq header
            if (buffer[0] == Convert.ToByte('H') && buffer[1] == Convert.ToByte('M') && buffer[2] == Convert.ToByte('3') && buffer[3] == Convert.ToByte('W'))
            {
                //sha1.TransformBlock(buffer, 0, buffer.Length, null, 0);
                Array.Copy(buffer, buffer_old, buffer.Length);
                bytesRead_old = bytesRead;
            }
            else
            {
                throw new Exception("Not a vaild map.");
            }

            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                //Construct a new temporiary bytes of 2 trunks, in case the header sign is splited.
                byte[] temp = new byte[buffer_old.Length + buffer.Length];
                Array.Copy(buffer_old, 0, temp, 0, buffer_old.Length);
                Array.Copy(buffer, 0, temp, buffer_old.Length, buffer.Length);

                //search for the block header 'NGIS'
                int index;
                if ((index = IndexOfBytes(temp, SIGNATURE_HEADER)) != -1)
                {
                    //if found!
                    Console.WriteLine("Found Signature.");
                    sha1.TransformBlock(temp, 0, index, null, 0);
                    findblockheader = true;
                    //dump signature
                    input.Position = input.Position - temp.Length + index + SIGNATURE_HEADER.Length;  //set the stream pos after 'NGIS'
                    signature_pos = input.Position - SIGNATURE_HEADER.Length;   //get the signature block starting pos
                    mapsignature = new byte[input.Length - input.Position];
                    input.Read(mapsignature, 0, mapsignature.Length);
                    Array.Reverse(mapsignature);
                    break;
                }
                else
                {
                    sha1.TransformBlock(buffer_old, 0, bytesRead_old, null, 0);
                    Array.Copy(buffer, buffer_old, buffer.Length);
                    bytesRead_old = bytesRead;
                }
            }

            if (!findblockheader) { sha1.TransformBlock(buffer_old, 0, bytesRead_old, null, 0); }
            sha1.TransformBlock(mapnamebytes, 0, mapnamebytes.Length, null, 0); //Add upper file name to the end
            sha1.TransformFinalBlock(buffer, 0, 0);

            //Calculate Hash:
            Console.WriteLine("SHA1:");
            maphash = new byte[sha1.Hash.Length];
            sha1.Hash.CopyTo(maphash, 0);
            input.Close();
            input.Dispose();
            Array.Reverse(maphash);
            Console.WriteLine(BitConverter.ToString(maphash));
            return signature_pos;
        }
        
        //=====================================================
        // Verify map signature data with public key
        //=====================================================
        public static byte[] VerifyData(byte[] BytesToVerify, string keypath)
        {
            //Load public key
            StreamReader sr = new StreamReader(keypath);
            string pubkeyaspem = sr.ReadToEnd();
            sr.Close();

            //Init openssl rsa component.
            CryptoKey d = CryptoKey.FromPublicKey(pubkeyaspem, null);
            RSA r = d.GetRSA();
            byte[] result = r.PublicDecrypt(BytesToVerify, OpenSSL.Crypto.RSA.Padding.None);
            r.Dispose();
            return result;
        }

        //=====================================================
        // Deconstruct raw signature data to map hash (remove padding)
        //=====================================================
        public static byte[] RemovePadding(byte[] RawSignature)
        {
            byte[] result = new byte[20];   //length of a SHA1 hash
            Array.ConstrainedCopy(RawSignature, RawSignature.Length - result.Length, result, 0, result.Length);
            Console.WriteLine("Dumpped SHA1:");
            Console.WriteLine(BitConverter.ToString(result));
            return result;
        }

        //=====================================================
        // Construct map hash to raw signature data (add padding)
        //=====================================================
        public static byte[] AddPadding(byte[] maphash)
        {
            byte[] result = new byte[256];   //length of a raw signature data

            //fill the byte array
            result[0] = 0x0B;
            for (int i = 1; i <= 235; i++) { result[i] = 0xBB; }

            Array.ConstrainedCopy(maphash, 0, result, 236, maphash.Length);
            return result;
        }

        //=====================================================
        // Sign map signature data(map hash) with private key
        //  - output in reversed order
        //=====================================================
        public static byte[] SignData(byte[] BytesToSign, string keypath)
        {
            //Load private key
            StreamReader sr = new StreamReader(keypath);
            string pvtkeyaspem = sr.ReadToEnd();
            sr.Close();

            //Init openssl rsa component.
            CryptoKey d = CryptoKey.FromPrivateKey(pvtkeyaspem, null);
            RSA r = d.GetRSA();
            byte[] result = r.PrivateEncrypt(BytesToSign, OpenSSL.Crypto.RSA.Padding.None);
            r.Dispose();
            Array.Reverse(result);
            return result;
        }

        //=====================================================
        // Add signature to the end of a map
        //=====================================================
        static public void MapAddSignature(string mappath, byte[] signature, long signature_pos = -1)
        {
            //backup
            string backuppath = Path.GetDirectoryName(mappath) + @"\" + Path.GetFileNameWithoutExtension(mappath) + "_bak" + Path.GetExtension(mappath);
            if (File.Exists(backuppath)) { File.Delete(backuppath); }
            File.Move(mappath, backuppath);

            //create new file
            if (signature_pos == -1)
            { File.Copy(backuppath, mappath); }
            else
            {
                Console.WriteLine("Found signature block, start ripping.");
                FileStream newfile = new FileStream(mappath, FileMode.CreateNew, FileAccess.ReadWrite);
                using (Stream ms = File.OpenRead(backuppath))
                {
                    byte[] buffer = new byte[1024 * 100];   //100k each trunk
                    int numBytesRead;
                    int n = 0;
                    while ((numBytesRead = ms.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (ms.Position >= signature_pos)   //reach block header
                        {
                            long pos = signature_pos - (buffer.Length * n);
                            newfile.Write(buffer, 0, (int)pos);
                            break;
                        }
                        else
                        { newfile.Write(buffer, 0, numBytesRead); }
                        n++;    //n = trunks_count - 1 (trunk index, started from zero)
                    }
                    ms.Close();
                    ms.Dispose();
                }
                newfile.Close();
                newfile.Dispose();
            }
            Console.WriteLine("Reconstructing map complete.");

            //add signature to the end of the map
            Application.DoEvents();
            Application.DoEvents();
            FileStream map = new FileStream(mappath, FileMode.Append, FileAccess.Write);
            map.Write(SIGNATURE_HEADER, 0, SIGNATURE_HEADER.Length); //write block header
            map.Write(signature, 0, signature.Length);  //write signature
            map.Close();
            map.Dispose();
            Console.WriteLine("Adding signature complete.");
        }
    }
}
