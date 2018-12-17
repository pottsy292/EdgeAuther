using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EdgeAuther
{
    internal class BuildStrings
    {
        public static string URLSafe(string Str)
        {
            return Str.Replace("+", "-").Replace("/", "_").Replace("=", "");
        }

        public static byte[] dauth_kek_05 = { 0x2f, 0x04, 0xf7, 0xc8, 0xba, 0x01, 0x93, 0xd7, 0xfc, 0xda, 0xc6, 0x0a, 0xa4, 0xb7, 0xd5, 0x05 };

        public static string Client_ID = "41f4a6491028e3c4";
        public static string UserAgent = "libcurl (nnHttp; 789f928b-138e-4b2f-afeb-1acae821d897; SDK 6.4.0.0; Add-on 6.4.0.0)";
        public static string Challenge = "key_generation=6";
        public const string SysDigest = "CusHY#00060200#-uAUBEUSc-Se5mvfhJsj3Krr9ayN7IyTX60_XcLsZkQ=";

        public static X509Certificate2 Cert = new X509Certificate2("nx_tls_client_cert.pfx", "switch");

        public static bool AcceptAllCertifications(object Input, X509Certificate Cert, X509Chain Chain, SslPolicyErrors Err) => true;

        public static string MakeReq(string URL, byte[] PostData)
        {
            try
            {
                ServicePointManager.ServerCertificateValidationCallback = AcceptAllCertifications;
                HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(URL);
                Request.ClientCertificates.Add(Cert);
                Request.Host = "dauth-lp1.ndas.srv.nintendo.net";
                Request.UserAgent = UserAgent;
                Request.Accept = "*/*";
                Request.ContentLength = PostData.Length;
                Request.ContentType = "application/x-www-form-urlencoded";
                Request.Method = "POST";
                Stream DataStream = Request.GetRequestStream();
                DataStream.Write(PostData, 0, PostData.Length);
                DataStream.Close();
                WebResponse Response = Request.GetResponse();
                StreamReader Reader = new StreamReader(Response.GetResponseStream());
                return Reader.ReadToEnd();
            }
            catch (WebException Ex)
            {
                var ErrorBody = new StreamReader(Ex.Response.GetResponseStream()).ReadToEnd();
                return ErrorBody;
            }
        }

        public static byte[] Decrypt(byte[] Data, byte[] Key)
        {
            RijndaelManaged Unwrap = new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                Key = Key,
                Padding = PaddingMode.None
            };
            var Decrypt = Unwrap.CreateDecryptor();
            byte[] Out = Decrypt.TransformFinalBlock(Data, 0, 16);
            return Out;
        }

        public static byte[] GenAESKekLiteEditionTM(byte[] DAuth_KEK, byte[] DAuth_Src)
        {
            return Decrypt(DAuth_Src, DAuth_KEK);
        }

        public static string BuildRequestString(string Challenge)
        {
            return $"challenge={Challenge}&client_id={Client_ID}&key_generation=6&system_version={SysDigest}";
        }

        public static string GenCMAC(byte[] Key, string RequestData)
        {
            return URLSafe(Convert.ToBase64String(GenAESCMAC.AESCMAC(Key, Encoding.UTF8.GetBytes(RequestData))));
        }

        public static byte[] PostAuthToken(string Data, string MAC)
        {
            return Encoding.UTF8.GetBytes($"{Data}&mac={MAC}");
        }
    }
}
