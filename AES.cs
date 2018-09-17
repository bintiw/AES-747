//---ASCII---
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace AES
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = "cece07f7ee9230e76ccf497bdbbdbc0a";     //Key For AES Encryption

            Console.WriteLine("Working...");
            encc(key);
            decc(key);
            Console.WriteLine("Done...");

            Console.ReadKey();


        }

        public static string ConvertAsciiToHex(string asciiString)  //Function to Convert ASCII to HEX
        {
            string hex = "";
            foreach (char c in asciiString)
            {
                int tmp = c;
                hex += String.Format("{0:X2}", (uint)System.Convert.ToUInt32(tmp.ToString()));
            }
            return hex;
        }

        public static string ConvertHextoAscii(string HexString)  //Function to Convert HEX to ASCII
        {
            string asciiString = "";
            for (int i = 0; i < HexString.Length; i += 2)
            {
                if (HexString.Length >= i + 2)
                {
                    String hs = HexString.Substring(i, 2);
                    asciiString = asciiString + System.Convert.ToChar(System.Convert.ToUInt32(HexString.Substring(i, 2), 16)).ToString();
                }
            }
            return asciiString;
        }

        public static void decc(string key)   //Funtion for AES Decryption TEXT
        {
            string filename = System.IO.Path.GetFullPath(Directory.GetCurrentDirectory() + @"\AES_result.txt");
            string text = File.ReadAllText(filename, Encoding.UTF8);
            text = ConvertAsciiToHex(text);
            string cipher = "";
            for (int i = 0; i < text.Length; i = i + 32)
            {
                string temp = text.Substring(i, 32);
                string aesenc = AES_Dec(key, temp);
                cipher = cipher + aesenc;
            }
            string cipherascii = ConvertHextoAscii(cipher);
            filename = System.IO.Path.GetFullPath(Directory.GetCurrentDirectory() + @"\AES_Plain.txt");
            System.IO.File.WriteAllText(filename, cipherascii);

        }


        public static void encc(string key)   //Function for AES Encryption TEXT
        {
            string filename = System.IO.Path.GetFullPath(Directory.GetCurrentDirectory() + @"\AES.txt");
            string text = File.ReadAllText(filename, Encoding.UTF8);

            if (text.Length % 16 != 0)
            {
                text = text + new string('#', ((text.Length / 16) + 1) * 16 - text.Length);

            }

            string cipher = "";
            text = ConvertAsciiToHex(text);
            for (int i = 0; i < text.Length; i = i + 32)
            {
                string temp = text.Substring(i, 32);
                string aesenc = AES_Enc(key, temp);
                cipher = cipher + aesenc;
            }
            string cipherascii = ConvertHextoAscii(cipher);
            Console.WriteLine(cipherascii);

            filename = System.IO.Path.GetFullPath(Directory.GetCurrentDirectory() + @"\AES_result.txt");
            System.IO.File.WriteAllText(filename, cipherascii);


        }
        public static string AES_Dec(string k, string p)  //AES Decryption Algorithm Implementation
        {
            string key = keyexpansion(k);
            string temp = p;
            temp = keyready(temp);
            temp = xor(keyready(key.Substring(320, 32)), temp);
            temp = invshiftrow(temp);
            temp = invsub(temp);

            for (int j = 288; j >= 32; j = j - 32)
            {
                temp = xor(keyready(key.Substring(j, 32)), temp);
                temp = invmixedcol(temp);
                temp = invshiftrow(temp);
                temp = invsub(temp);
            }

            temp = keyready(temp);
            temp = xor(key.Substring(0, 32), temp);
            return (temp);

        }


        public static string AES_Enc(string k, string p)  //AES Encryption Algorithm Implementation
        {
            string key = keyexpansion(k);
            string temp = "";
            temp = xor(key.Substring(0, 32), p);
            temp = keyready(temp);

            for (int j = 32; j <= 288; j = j + 32)
            {

                temp = sub(temp);
                temp = shiftrow(temp);
                temp = mixedcol(temp);
                temp = xor(keyready(key.Substring(j, 32)), temp);

            }

            temp = sub(temp);
            temp = shiftrow(temp);
            temp = xor(keyready(key.Substring(320, 32)), temp);
            temp = keyready(temp);

            return (temp);

        }
// Support Functions for Algorithms
        public static string keyready(string a)
        {
            return ("" + a[0] + a[1] + a[8] + a[9] + a[16] + a[17] + a[24] + a[25] + a[2] + a[3] + a[10] + a[11] + a[18] + a[19] + a[26] + a[27] + a[4] + a[5] + a[12] + a[13] + a[20] + a[21] + a[28] + a[29] + a[6] + a[7] + a[14] + a[15] + a[22] + a[23] + a[30] + a[31]);

        }

        public static string sub(string a)
        {
            string temp = "";
            for (int i = 0; i < a.Length; i = i + 2)
            {
                string temp1 = inverse("" + a[i] + a[i + 1]);
                temp1 = Reverse(temp1);
                temp1 = box(temp1, "10001111", "11000110");
                temp1 = Reverse(temp1);
                temp1 = Convert.ToInt32(temp1, 2).ToString("X").Trim().PadLeft(2, '0');
                temp = temp + temp1;
                temp1 = "";
            }
            return (temp);

        }

        public static string invsub(string a)
        {
            string temp = "";
            for (int i = 0; i < a.Length; i = i + 2)
            {
                string temp1 = ("" + a[i] + a[i + 1]);
                Int32 invn = Convert.ToInt32(temp1, 16);
                temp1 = Reverse(Convert.ToString(invn, 2).PadLeft(8, '0'));
                temp1 = box(temp1, "00100101", "10100000");
                temp1 = Reverse(temp1);
                temp1 = inverse(Convert.ToInt32(temp1, 2).ToString("X"));
                temp1 = Convert.ToInt32(temp1, 2).ToString("X").PadLeft(2, '0');
                temp = temp + temp1;
                temp1 = "";
            }
            return (temp);

        }

        public static string xor(string a, string b)
        {
            string result = "";

            for (int i = 0; i < a.Length; i++)
            {
                string temp = (Convert.ToInt16(Convert.ToString(a[i]), 16) ^ Convert.ToInt16(Convert.ToString(b[i]), 16)).ToString("X");

                result += temp;
            }
            return result;
        }

        public static string invshiftrow(string a)
        {
            string temp1, temp2, temp3, temp4;
            temp1 = a.Substring(0, 8);
            temp2 = a.Substring(8, 8);
            temp3 = a.Substring(16, 8);
            temp4 = a.Substring(24, 8);
            string temp = "" + temp2[6] + temp2[7] + temp2[0] + temp2[1] + temp2[2] + temp2[3] + temp2[4] + temp2[5];
            temp2 = temp;
            temp = "" + temp3[4] + temp3[5] + temp3[6] + temp3[7] + temp3[0] + temp3[1] + temp3[2] + temp3[3];
            temp3 = temp;
            temp = "" + temp4[2] + temp4[3] + temp4[4] + temp4[5] + temp4[6] + temp4[7] + temp4[0] + temp4[1];
            temp4 = temp;
            return ("" + temp1 + temp2 + temp3 + temp4);
        }


        public static string shiftrow(string a)
        {
            string temp1, temp2, temp3, temp4;
            temp1 = a.Substring(0, 8);
            temp2 = a.Substring(8, 8);
            temp3 = a.Substring(16, 8);
            temp4 = a.Substring(24, 8);
            string temp = "" + temp2[2] + temp2[3] + temp2[4] + temp2[5] + temp2[6] + temp2[7] + temp2[0] + temp2[1];
            temp2 = temp;
            temp = "" + temp3[4] + temp3[5] + temp3[6] + temp3[7] + temp3[0] + temp3[1] + temp3[2] + temp3[3];
            temp3 = temp;
            temp = "" + temp4[6] + temp4[7] + temp4[0] + temp4[1] + temp4[2] + temp4[3] + temp4[4] + temp4[5];
            temp4 = temp;
            return ("" + temp1 + temp2 + temp3 + temp4);
        }






        public static string keyexpansion(string a)
        {
            IList<string> result = new List<string>();
            string temp = "";
            string[] rcon = { "00", "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };
            string w0 = a.Substring(0, 8);
            string w1 = a.Substring(8, 8);
            string w2 = a.Substring(16, 8);
            string w3 = a.Substring(24, 8);

            result.Add(w0);
            result.Add(w1);
            result.Add(w2);
            result.Add(w3);

            for (int i = 4; i < 44; i++)
            {

                if (i % 4 == 0)
                {
                    string second = result[i - 4];

                    string first = result[i - 1];

                    string temp1 = first.Substring(2, first.Length - 2);
                    first = first.Substring(0, 2);
                    first = temp1 + first;

                    string inv1 = first.Substring(0, 2);
                    inv1 = inverse(inv1);
                    inv1 = Reverse(inv1);
                    string sbox_result1 = box(inv1, "10001111", "11000110");
                    sbox_result1 = Reverse(sbox_result1);
                    sbox_result1 = Convert.ToInt32(sbox_result1, 2).ToString("X").PadLeft(2, '0');


                    temp1 = "";
                    temp1 += sbox_result1;

                    inv1 = first.Substring(2, 2);
                    inv1 = inverse(inv1);
                    inv1 = Reverse(inv1);
                    sbox_result1 = box(inv1, "10001111", "11000110");
                    sbox_result1 = Reverse(sbox_result1);
                    sbox_result1 = Convert.ToInt32(sbox_result1, 2).ToString("X").PadLeft(2, '0');
                    temp1 += sbox_result1;

                    inv1 = first.Substring(4, 2);
                    inv1 = inverse(inv1);
                    inv1 = Reverse(inv1);
                    sbox_result1 = box(inv1, "10001111", "11000110");
                    sbox_result1 = Reverse(sbox_result1);
                    sbox_result1 = Convert.ToInt32(sbox_result1, 2).ToString("X").PadLeft(2, '0');
                    temp1 += sbox_result1;



                    inv1 = first.Substring(6, 2);
                    inv1 = inverse(inv1);
                    inv1 = Reverse(inv1);
                    sbox_result1 = box(inv1, "10001111", "11000110");
                    sbox_result1 = Reverse(sbox_result1);
                    sbox_result1 = Convert.ToInt32(sbox_result1, 2).ToString("X").PadLeft(2, '0');
                    temp1 += sbox_result1;

                    temp1 = xor(temp1, rcon[i / 4].PadRight(temp1.Length, '0'));

                    temp1 = xor(temp1, second);

                    result.Add(temp1.PadLeft(8, '0'));
                }
                else
                {

                    string second = result[i - 4];
                    string first = result[i - 1];
                    result.Add(xor(first, second).PadLeft(8, '0'));
                }

            }

            foreach (var el in result)
            {
                temp = temp + el;

            }

            return temp;
        }



        public static string Reverse(string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        public static int GCD(int a, int b)
        {
            if (a == 0)
                return b;
            if (b == 0)
                return a;

            if (a > b)
                return GCD(a % b, b);
            else
                return GCD(a, b % a);
        }





// Galios Multiplication
        public static string gmul(string c, int b)
        {

            string[] E = { "01", "03", "05", "0f", "11", "33", " 55 ", " ff ", " 1a ", " 2e ", " 72 ", " 96 ", " a1 ", " f8 ", " 13 ", " 35 ", " 5f ", " e1 ", " 38 ", " 48 ", " d8 ", " 73 ", " 95 ", " a4 ", " f7 ", " 02 ", " 06 ", " 0a ", " 1e ", " 22 ", " 66 ", " aa ", " e5 ", " 34 ", " 5c ", " e4 ", " 37 ", " 59 ", " eb ", " 26 ", " 6a ", " be ", " d9 ", " 70 ", " 90 ", " ab ", " e6 ", " 31 ", " 53 ", " f5 ", " 04 ", " 0c ", " 14 ", " 3c ", " 44 ", " cc ", " 4f ", " d1 ", " 68 ", " b8 ", " d3 ", " 6e ", " b2 ", " cd ", " 4c ", " d4 ", " 67 ", " a9 ", " e0 ", " 3b ", " 4d ", " d7 ", " 62 ", " a6 ", " f1 ", " 08 ", " 18 ", " 28 ", " 78 ", " 88 ", " 83 ", " 9e ", " b9 ", " d0 ", " 6b ", " bd ", " dc ", " 7f ", " 81 ", " 98 ", " b3 ", " ce ", " 49 ", " db ", " 76 ", " 9a ", " b5 ", " c4 ", " 57 ", " f9 ", " 10 ", " 30 ", " 50 ", " f0 ", " 0b ", " 1d ", " 27 ", " 69 ", " bb ", " d6 ", " 61 ", " a3 ", " fe ", " 19 ", " 2b ", " 7d ", " 87 ", " 92 ", " ad ", " ec ", " 2f ", " 71 ", " 93 ", " ae ", " e9 ", " 20 ", " 60 ", " a0 ", " fb ", " 16 ", " 3a ", " 4e ", " d2 ", " 6d ", " b7 ", " c2 ", " 5d ", " e7 ", " 32 ", " 56 ", " fa ", " 15 ", " 3f ", " 41 ", " c3 ", " 5e ", " e2 ", " 3d ", " 47 ", " c9 ", " 40 ", " c0 ", " 5b ", " ed ", " 2c ", " 74 ", " 9c ", " bf ", " da ", " 75 ", " 9f ", " ba ", " d5 ", " 64 ", " ac ", " ef ", " 2a ", " 7e ", " 82 ", " 9d ", " bc ", " df ", " 7a ", " 8e ", " 89 ", " 80 ", " 9b ", " b6 ", " c1 ", " 58 ", " e8 ", " 23 ", " 65 ", " af ", " ea ", " 25 ", " 6f ", " b1 ", " c8 ", " 43 ", " c5 ", " 54 ", " fc ", " 1f ", " 21 ", " 63 ", " a5 ", " f4 ", " 07 ", " 09 ", " 1b ", " 2d ", " 77 ", " 99 ", " b0 ", " cb ", " 46 ", " ca ", " 45 ", " cf ", " 4a ", " de ", " 79 ", " 8b ", " 86 ", " 91 ", " a8 ", " e3 ", " 3e ", " 42 ", " c6 ", " 51 ", " f3 ", " 0e ", " 12 ", " 36 ", " 5a ", " ee ", " 29 ", " 7b ", " 8d ", " 8c ", " 8f ", " 8a ", " 85 ", " 94 ", " a7 ", " f2 ", " 0d ", " 17 ", " 39 ", " 4b ", " dd ", " 7c ", " 84 ", " 97 ", " a2 ", " fd ", " 1c ", " 24 ", " 6c ", " b4 ", " c7 ", " 52 ", " f6 ", " 01" };
            string[] L = { " ", " 00 ", " 19 ", " 01 ", " 32 ", " 02 ", " 1a ", " c6 ", " 4b ", " c7 ", " 1b ", " 68 ", " 33 ", " ee ", " df ", " 03 ", " 64 ", " 04 ", " e0 ", " 0e ", " 34 ", " 8d ", " 81 ", " ef ", " 4c ", " 71 ", " 08 ", " c8 ", " f8 ", " 69 ", " 1c ", " c1 ", " 7d ", " c2 ", " 1d ", " b5 ", " f9 ", " b9 ", " 27 ", " 6a ", " 4d ", " e4 ", " a6 ", " 72 ", " 9a ", " c9 ", " 09 ", " 78 ", " 65 ", " 2f ", " 8a ", " 05 ", " 21 ", " 0f ", " e1 ", " 24 ", " 12 ", " f0 ", " 82 ", " 45 ", " 35 ", " 93 ", " da ", " 8e ", " 96 ", " 8f ", " db ", " bd ", " 36 ", " d0 ", " ce ", " 94 ", " 13 ", " 5c ", " d2 ", " f1 ", " 40 ", " 46 ", " 83 ", " 38 ", " 66 ", " dd ", " fd ", " 30 ", " bf ", " 06 ", " 8b ", " 62 ", " b3 ", " 25 ", " e2 ", " 98 ", " 22 ", " 88 ", " 91 ", " 10 ", " 7e ", " 6e ", " 48 ", " c3 ", " a3 ", " b6 ", " 1e ", " 42 ", " 3a ", " 6b ", " 28 ", " 54 ", " fa ", " 85 ", " 3d ", " ba ", " 2b ", " 79 ", " 0a ", " 15 ", " 9b ", " 9f ", " 5e ", " ca ", " 4e ", " d4 ", " ac ", " e5 ", " f3 ", " 73 ", " a7 ", " 57 ", " af ", " 58 ", " a8 ", " 50 ", " f4 ", " ea ", " d6 ", " 74 ", " 4f ", " ae ", " e9 ", " d5 ", " e7 ", " e6 ", " ad ", " e8 ", " 2c ", " d7 ", " 75 ", " 7a ", " eb ", " 16 ", " 0b ", " f5 ", " 59 ", " cb ", " 5f ", " b0 ", " 9c ", " a9 ", " 51 ", " a0 ", " 7f ", " 0c ", " f6 ", " 6f ", " 17 ", " c4 ", " 49 ", " ec ", " d8 ", " 43 ", " 1f ", " 2d ", " a4 ", " 76 ", " 7b ", " b7 ", " cc ", " bb ", " 3e ", " 5a ", " fb ", " 60 ", " b1 ", " 86 ", " 3b ", " 52 ", " a1 ", " 6c ", " aa ", " 55 ", " 29 ", " 9d ", " 97 ", " b2 ", " 87 ", " 90 ", " 61 ", " be ", " dc ", " fc ", " bc ", " 95 ", " cf ", " cd ", " 37 ", " 3f ", " 5b ", " d1 ", " 53 ", " 39 ", " 84 ", " 3c ", " 41 ", " a2 ", " 6d ", " 47 ", " 14 ", " 2a ", " 9e ", " 5d ", " 56 ", " f2 ", " d3 ", " ab ", " 44 ", " 11 ", " 92 ", " d9 ", " 23 ", " 20 ", " 2e ", " 89 ", " b4 ", " 7c ", " b8 ", " 26 ", " 77 ", " 99 ", " e3 ", " a5 ", " 67 ", " 4a ", " ed ", " de ", " c5 ", " 31 ", " fe ", " 18 ", " 0d ", " 63 ", " 8c ", " 80 ", " c0 ", " f7 ", " 70 ", " 07" };

            int a = Convert.ToInt16(c, 16);
            int t = 0;
            if (a == 0 || b == 0) return "0";
            t = Convert.ToInt16(L[a].Trim(), 16) + Convert.ToInt16(L[b].Trim(), 16);
            if (t > 255) t = t - 255;
            return E[t].Trim();
        }

        public static string mixedcol(string a)
        {
            string temp = "";

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 2), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 3), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 1), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 1), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 2), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 3), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 1), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 1), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 2), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 3), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 1), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 1), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 2), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 3), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 1), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 1), 16)).ToString("X").PadLeft(2, '0');

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 1), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 2), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 3), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 1), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 1), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 2), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 3), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 1), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 1), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 2), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 3), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 1), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 1), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 2), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 3), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 1), 16)).ToString("X").PadLeft(2, '0');

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 1), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 1), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 2), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 3), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 1), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 1), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 2), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 3), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 1), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 1), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 2), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 3), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 1), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 1), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 2), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 3), 16)).ToString("X").PadLeft(2, '0');

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 3), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 1), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 1), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 2), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 3), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 1), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 1), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 2), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 3), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 1), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 1), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 2), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 3), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 1), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 1), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 2), 16)).ToString("X").PadLeft(2, '0');

            return temp;
        }


        public static string invmixedcol(string a)
        {
            string temp = "";

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 14), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 11), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 13), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 9), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 14), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 11), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 13), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 9), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 14), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 11), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 13), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 9), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 14), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 11), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 13), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 9), 16)).ToString("X").PadLeft(2, '0');

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 9), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 14), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 11), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 13), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 9), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 14), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 11), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 13), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 9), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 14), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 11), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 13), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 9), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 14), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 11), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 13), 16)).ToString("X").PadLeft(2, '0');

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 13), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 9), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 14), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 11), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 13), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 9), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 14), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 11), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 13), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 9), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 14), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 11), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 13), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 9), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 14), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 11), 16)).ToString("X").PadLeft(2, '0');

            temp += (Convert.ToInt32(gmul("" + a[0] + a[1], 11), 16) ^ Convert.ToInt32(gmul("" + a[8] + a[9], 13), 16) ^ Convert.ToInt32(gmul("" + a[16] + a[17], 9), 16) ^ Convert.ToInt32(gmul("" + a[24] + a[25], 14), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[2] + a[3], 11), 16) ^ Convert.ToInt32(gmul("" + a[10] + a[11], 13), 16) ^ Convert.ToInt32(gmul("" + a[18] + a[19], 9), 16) ^ Convert.ToInt32(gmul("" + a[26] + a[27], 14), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[4] + a[5], 11), 16) ^ Convert.ToInt32(gmul("" + a[12] + a[13], 13), 16) ^ Convert.ToInt32(gmul("" + a[20] + a[21], 9), 16) ^ Convert.ToInt32(gmul("" + a[28] + a[29], 14), 16)).ToString("X").PadLeft(2, '0');
            temp += (Convert.ToInt32(gmul("" + a[6] + a[7], 11), 16) ^ Convert.ToInt32(gmul("" + a[14] + a[15], 13), 16) ^ Convert.ToInt32(gmul("" + a[22] + a[23], 9), 16) ^ Convert.ToInt32(gmul("" + a[30] + a[31], 14), 16)).ToString("X").PadLeft(2, '0');

            return temp;
        }



        static string inverse(string a)
        {
            if (a == "00" | a =="0")
                return "00";
            string[] exp = { "01", "03", "05", "0f", "11", "33", " 55 ", " ff ", " 1a ", " 2e ", " 72 ", " 96 ", " a1 ", " f8 ", " 13 ", " 35 ", " 5f ", " e1 ", " 38 ", " 48 ", " d8 ", " 73 ", " 95 ", " a4 ", " f7 ", " 02 ", " 06 ", " 0a ", " 1e ", " 22 ", " 66 ", " aa ", " e5 ", " 34 ", " 5c ", " e4 ", " 37 ", " 59 ", " eb ", " 26 ", " 6a ", " be ", " d9 ", " 70 ", " 90 ", " ab ", " e6 ", " 31 ", " 53 ", " f5 ", " 04 ", " 0c ", " 14 ", " 3c ", " 44 ", " cc ", " 4f ", " d1 ", " 68 ", " b8 ", " d3 ", " 6e ", " b2 ", " cd ", " 4c ", " d4 ", " 67 ", " a9 ", " e0 ", " 3b ", " 4d ", " d7 ", " 62 ", " a6 ", " f1 ", " 08 ", " 18 ", " 28 ", " 78 ", " 88 ", " 83 ", " 9e ", " b9 ", " d0 ", " 6b ", " bd ", " dc ", " 7f ", " 81 ", " 98 ", " b3 ", " ce ", " 49 ", " db ", " 76 ", " 9a ", " b5 ", " c4 ", " 57 ", " f9 ", " 10 ", " 30 ", " 50 ", " f0 ", " 0b ", " 1d ", " 27 ", " 69 ", " bb ", " d6 ", " 61 ", " a3 ", " fe ", " 19 ", " 2b ", " 7d ", " 87 ", " 92 ", " ad ", " ec ", " 2f ", " 71 ", " 93 ", " ae ", " e9 ", " 20 ", " 60 ", " a0 ", " fb ", " 16 ", " 3a ", " 4e ", " d2 ", " 6d ", " b7 ", " c2 ", " 5d ", " e7 ", " 32 ", " 56 ", " fa ", " 15 ", " 3f ", " 41 ", " c3 ", " 5e ", " e2 ", " 3d ", " 47 ", " c9 ", " 40 ", " c0 ", " 5b ", " ed ", " 2c ", " 74 ", " 9c ", " bf ", " da ", " 75 ", " 9f ", " ba ", " d5 ", " 64 ", " ac ", " ef ", " 2a ", " 7e ", " 82 ", " 9d ", " bc ", " df ", " 7a ", " 8e ", " 89 ", " 80 ", " 9b ", " b6 ", " c1 ", " 58 ", " e8 ", " 23 ", " 65 ", " af ", " ea ", " 25 ", " 6f ", " b1 ", " c8 ", " 43 ", " c5 ", " 54 ", " fc ", " 1f ", " 21 ", " 63 ", " a5 ", " f4 ", " 07 ", " 09 ", " 1b ", " 2d ", " 77 ", " 99 ", " b0 ", " cb ", " 46 ", " ca ", " 45 ", " cf ", " 4a ", " de ", " 79 ", " 8b ", " 86 ", " 91 ", " a8 ", " e3 ", " 3e ", " 42 ", " c6 ", " 51 ", " f3 ", " 0e ", " 12 ", " 36 ", " 5a ", " ee ", " 29 ", " 7b ", " 8d ", " 8c ", " 8f ", " 8a ", " 85 ", " 94 ", " a7 ", " f2 ", " 0d ", " 17 ", " 39 ", " 4b ", " dd ", " 7c ", " 84 ", " 97 ", " a2 ", " fd ", " 1c ", " 24 ", " 6c ", " b4 ", " c7 ", " 52 ", " f6 ", " 01" };
            string[] log = { " ", " 00 ", " 19 ", " 01 ", " 32 ", " 02 ", " 1a ", " c6 ", " 4b ", " c7 ", " 1b ", " 68 ", " 33 ", " ee ", " df ", " 03 ", " 64 ", " 04 ", " e0 ", " 0e ", " 34 ", " 8d ", " 81 ", " ef ", " 4c ", " 71 ", " 08 ", " c8 ", " f8 ", " 69 ", " 1c ", " c1 ", " 7d ", " c2 ", " 1d ", " b5 ", " f9 ", " b9 ", " 27 ", " 6a ", " 4d ", " e4 ", " a6 ", " 72 ", " 9a ", " c9 ", " 09 ", " 78 ", " 65 ", " 2f ", " 8a ", " 05 ", " 21 ", " 0f ", " e1 ", " 24 ", " 12 ", " f0 ", " 82 ", " 45 ", " 35 ", " 93 ", " da ", " 8e ", " 96 ", " 8f ", " db ", " bd ", " 36 ", " d0 ", " ce ", " 94 ", " 13 ", " 5c ", " d2 ", " f1 ", " 40 ", " 46 ", " 83 ", " 38 ", " 66 ", " dd ", " fd ", " 30 ", " bf ", " 06 ", " 8b ", " 62 ", " b3 ", " 25 ", " e2 ", " 98 ", " 22 ", " 88 ", " 91 ", " 10 ", " 7e ", " 6e ", " 48 ", " c3 ", " a3 ", " b6 ", " 1e ", " 42 ", " 3a ", " 6b ", " 28 ", " 54 ", " fa ", " 85 ", " 3d ", " ba ", " 2b ", " 79 ", " 0a ", " 15 ", " 9b ", " 9f ", " 5e ", " ca ", " 4e ", " d4 ", " ac ", " e5 ", " f3 ", " 73 ", " a7 ", " 57 ", " af ", " 58 ", " a8 ", " 50 ", " f4 ", " ea ", " d6 ", " 74 ", " 4f ", " ae ", " e9 ", " d5 ", " e7 ", " e6 ", " ad ", " e8 ", " 2c ", " d7 ", " 75 ", " 7a ", " eb ", " 16 ", " 0b ", " f5 ", " 59 ", " cb ", " 5f ", " b0 ", " 9c ", " a9 ", " 51 ", " a0 ", " 7f ", " 0c ", " f6 ", " 6f ", " 17 ", " c4 ", " 49 ", " ec ", " d8 ", " 43 ", " 1f ", " 2d ", " a4 ", " 76 ", " 7b ", " b7 ", " cc ", " bb ", " 3e ", " 5a ", " fb ", " 60 ", " b1 ", " 86 ", " 3b ", " 52 ", " a1 ", " 6c ", " aa ", " 55 ", " 29 ", " 9d ", " 97 ", " b2 ", " 87 ", " 90 ", " 61 ", " be ", " dc ", " fc ", " bc ", " 95 ", " cf ", " cd ", " 37 ", " 3f ", " 5b ", " d1 ", " 53 ", " 39 ", " 84 ", " 3c ", " 41 ", " a2 ", " 6d ", " 47 ", " 14 ", " 2a ", " 9e ", " 5d ", " 56 ", " f2 ", " d3 ", " ab ", " 44 ", " 11 ", " 92 ", " d9 ", " 23 ", " 20 ", " 2e ", " 89 ", " b4 ", " 7c ", " b8 ", " 26 ", " 77 ", " 99 ", " e3 ", " a5 ", " 67 ", " 4a ", " ed ", " de ", " c5 ", " 31 ", " fe ", " 18 ", " 0d ", " 63 ", " 8c ", " 80 ", " c0 ", " f7 ", " 70 ", " 07" };
            
            
            int index = Convert.ToInt32(a, 16);
            
            string loga = log[index].Trim();

            index = 255 - Convert.ToInt32(loga, 16);

            loga = exp[index].Trim();
            
            int inv = Convert.ToInt32(loga, 16);

            return Convert.ToString(inv, 2).PadLeft(8, '0');

        }


        static string box(string plain, string mat, string bias)
        {

            if (plain == "00")
            {
                if (mat == "10001111")
                    return "11000110";
                else
                    return "00100101";


            }

            string matrix = "";
            string cipher = "";
            int temp = 0;
            for (int i = 0; i < mat.Length; i++)
            {
                temp = 0;
                for (int j = 0; j < mat.Length; j++)
                {
                    temp += (Convert.ToInt16(Convert.ToString(mat[j])) * Convert.ToInt16(Convert.ToString(plain[j])));
                }
                temp += Convert.ToInt16(Convert.ToString(bias[i]));


                if (temp % 2 == 0) { cipher += '0'; }
                else { cipher += '1'; }

                matrix = mat.Substring(0, mat.Length - 1);

                mat = mat[mat.Length - 1] + matrix;

            }

            return cipher;

        }

    }
}
