using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Snipr_Config_Decryptor {
    class Program {
        static void Main(string[] args) => File.WriteAllText(Path.GetFileNameWithoutExtension(args[0]) + "-decrypted.json", ConfigDecrypt(File.ReadAllText(args[0])));

        public static string ConfigDecrypt(string decryptme) {
            string password = "Rk_H9#2Uv$AHb%*Q9PrYZ46^C9DQFg+*5FsUBbrf"; //40 chars
            byte[] rawBytes = Convert.FromBase64String(decryptme);
            byte[] rgbIV = rawBytes.Skip(32).Take(32).ToArray();
            byte[] encBuffer = rawBytes.Skip(64).Take(rawBytes.Length - 64).ToArray();
            byte[] bytes = new Rfc2898DeriveBytes(password, rawBytes.Take(32).ToArray(), 1000).GetBytes(32);
            using (RijndaelManaged rijndaelManaged = new RijndaelManaged()) {
                rijndaelManaged.BlockSize = 256;
                rijndaelManaged.Mode = CipherMode.CBC; //ECB 4 netguard
                rijndaelManaged.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor(bytes, rgbIV)) {
                    byte[] buffer = new byte[encBuffer.Length];
                    return Encoding.UTF8.GetString(buffer, 0,
                        new CryptoStream(new MemoryStream(encBuffer), cryptoTransform, CryptoStreamMode.Read).Read(buffer, 0, buffer.Length));
                }
            }
        }
    }
}
/* Credits to Wadu */