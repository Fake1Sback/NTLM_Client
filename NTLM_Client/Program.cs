using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace NTLM_Client
{
    class Program
    {
        static void Main(string[] args)
        {
            HttpClient httpClient = new HttpClient();
            string RequestUri = "http://192.168.1.45:5000";
            string HostHeader = "192.168.1.45:5000";


            HttpRequestMessage httpRequest1 = new HttpRequestMessage();
            httpRequest1.Method = HttpMethod.Get;
            httpRequest1.RequestUri = new Uri(RequestUri);
            httpRequest1.Headers.Add("Host", HostHeader);
            httpRequest1.Headers.Add("Test", "Test");
            HttpResponseMessage response1 = httpClient.SendAsync(httpRequest1).Result;

            if (response1.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("Authorizing...");

                NTLM_Negotiate_Message negotiateMessage = new NTLM_Negotiate_Message("WORKGROUP", "ComputerName"); //Workgroup and computer name like DESKTOP-....
                HttpRequestMessage httpRequest2 = new HttpRequestMessage();
                httpRequest2.Method = HttpMethod.Get;
                httpRequest2.RequestUri = new Uri(RequestUri);
                httpRequest2.Headers.Add("Host", HostHeader);
                httpRequest2.Headers.Add("Test", "Test");
                httpRequest2.Headers.Add("Authorization", "NTLM " + negotiateMessage.GetWholeMessage());
                HttpResponseMessage response2 = httpClient.SendAsync(httpRequest2).Result;

                Console.WriteLine(response2.Content);
                NTLM_Challenge_Message challengeMessage = new NTLM_Challenge_Message(response2.Headers.GetValues("WWW-Authenticate").ToList().First().Split(' ').Last());

                NTLM_Authenticate_Message authenticate = new NTLM_Authenticate_Message(negotiateMessage, challengeMessage, "Alex", "", "ComputerName", "123", false);
                HttpRequestMessage httpRequest3 = new HttpRequestMessage();
                httpRequest3.Method = HttpMethod.Get;
                httpRequest3.RequestUri = new Uri(RequestUri);
                httpRequest3.Headers.Add("Host", HostHeader);
                httpRequest3.Headers.Add("Test", "Test");
                httpRequest3.Headers.Add("Authorization", "NTLM " + authenticate.GetWholeMessage());
                HttpResponseMessage response3 = httpClient.SendAsync(httpRequest3).Result;
            }
        }
    }

    public class NTLM_Negotiate_Message
    {
        public NTLM_Negotiate_Message(string DomainNameString,string WorkstationNameString)
        {
            GenerateFlags();
            GenerateDomainNameBytes(DomainNameString);
            GenerateWorkstationNameBytes(WorkstationNameString);
            GenerateVersion();

            WholeMessage.AddRange(Signature);
            WholeMessage.AddRange(MessageType);
            WholeMessage.AddRange(Flags);
            WholeMessage.AddRange(DomainNameLen);
            WholeMessage.AddRange(DomainNameMaxLen);
            WholeMessage.AddRange(DomainNameOffset);
            WholeMessage.AddRange(WorkstationLen);
            WholeMessage.AddRange(WorkstationMaxLen);
            WholeMessage.AddRange(WorkstationBufferOffset);
            WholeMessage.AddRange(Version);
            WholeMessage.AddRange(DomainName);
            WholeMessage.AddRange(WorkstationName);
        }

        private List<byte> WholeMessage = new List<byte>();

        private byte[] Signature = new byte[] { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00 };  //'N' 'T' 'L' 'M' 'S' 'S' 'P' '\0'
        private byte[] MessageType = new byte[4] { 0x01, 0x00, 0x00, 0x00 };
        private byte[] Flags = new byte[4] { 3, 50, 128, 162 };

        private byte[] DomainNameLen = new byte[2] { 0x00, 0x09 };   //Workgroup
        private byte[] DomainNameMaxLen = new byte[2] { 0x00, 0x09 };
        private byte[] DomainNameOffset = new byte[4] { 0x00, 0x00, 0x00, 0x28 };

        private byte[] WorkstationLen = new byte[2] { 0x00, 0x0F };
        private byte[] WorkstationMaxLen = new byte[2] { 0x00, 0x0F };
        private byte[] WorkstationBufferOffset = new byte[4] {0x00,0x00,0x00,0x31};

        private byte[] Version;
        private byte[] DomainName;
        private byte[] WorkstationName;

        public string GetWholeMessage()
        {
            return Convert.ToBase64String(WholeMessage.ToArray());
        }

        public byte[] GetBytes()
        {
            return WholeMessage.ToArray();
        }

        private void GenerateDomainNameBytes(string DomainName)
        {
            this.DomainName = Encoding.UTF8.GetBytes(DomainName);
            this.DomainNameLen = BitConverter.GetBytes(Convert.ToUInt16(this.DomainName.Length));
            this.DomainNameMaxLen = BitConverter.GetBytes(Convert.ToUInt16(this.DomainName.Length));
            this.DomainNameOffset = BitConverter.GetBytes(40);
        }

        private void GenerateWorkstationNameBytes(string WorkstationName)
        {
            this.WorkstationName = Encoding.UTF8.GetBytes(WorkstationName);
            this.WorkstationLen = BitConverter.GetBytes(Convert.ToUInt16(this.WorkstationName.Length));
            this.WorkstationMaxLen = BitConverter.GetBytes(Convert.ToUInt16(this.WorkstationName.Length));
            this.WorkstationBufferOffset = BitConverter.GetBytes(40 + BitConverter.ToInt16(this.DomainNameLen));
        }

        private void GenerateFlags()
        {
            BitArray bitArray = new BitArray(new byte[4]);
            bitArray[0] = true; //W Negotiate 56
            bitArray[1] = false; //V Negotiate Key Exchange
            bitArray[2] = true; //U Negotiate 128
            bitArray[3] = false; //R1
            bitArray[4] = false; //R2
            bitArray[5] = false; //R3
            bitArray[6] = true; //T Negotiate version
            bitArray[7] = false; //R4

            bitArray[8] = false; //S Negotiate Target Info
            bitArray[9] = false; //R Request Non-NT Session
            bitArray[10] = false; //R5
            bitArray[11] = false; //Q Negotiate Identify
            bitArray[12] = true; //P Negotiate Extended Security
            bitArray[13] = false; // Target type share
            bitArray[14] = false; // Target type server
            bitArray[15] = false; //N Target type domain

            bitArray[16] = false; //M Negotiate always sign
            bitArray[17] = false; //R6
            bitArray[18] = true; //L Negotiate OEM Workstation Supplied
            bitArray[19] = true; //K Negotiate OEM Domain Supplied
            bitArray[20] = false; //J //Negotiate anonymous
            bitArray[21] = false; // Negotiate NT Only
            bitArray[22] = true; //H Negotiate NTLM Key
            bitArray[23] = false; //R9

            bitArray[24] = false; //G Negotiate LAN Manager Key
            bitArray[25] = false; //F Negotiate Datagram
            bitArray[26] = false; //E Negotiate Seal
            bitArray[27] = false; //D Negotiate Sign
            bitArray[28] = false; //R10
            bitArray[29] = true; //C Request Target
            bitArray[30] = true; //B Negotiate OEM
            bitArray[31] = true; //A Negotiate Unicode 

            BitArray bitArray2 = new BitArray(32);
            int index = 31;
            for(int i = 0;i < bitArray.Length; i++)
            {
                bitArray2[i] = bitArray[index];
                index -= 1;
            }

            bitArray2.CopyTo(Flags, 0);
        }

        private void GenerateVersion()
        {
            byte ProductMajorVersion = 0x0A;
            byte ProductMinorVersion = 0x00;
            byte[] ProductBuild = new byte[2] { 0x61, 0x4a };
            byte[] Reserved = new byte[3];
            byte NTLMRevisionCurrent = 0x0F;

            List<byte> versionBytes = new List<byte>();
            versionBytes.Add(ProductMajorVersion);
            versionBytes.Add(ProductMinorVersion);
            versionBytes.AddRange(ProductBuild);
            versionBytes.AddRange(Reserved);
            versionBytes.Add(NTLMRevisionCurrent);
            this.Version = versionBytes.ToArray();
        }
    }

    public class NTLM_Challenge_Message
    {

        public NTLM_Challenge_Message(string Base64Response)
        {
            WholeMessage = Convert.FromBase64String(Base64Response);
            byte[] bytes = WholeMessage;
            Signature = bytes[0..8];
            MessageType = bytes[8..12];
            TargetNameLen = bytes[12..14];
            TargetNameMaxLen = bytes[14..16];
            TargetNameBufferOffset = bytes[16..20];
            Flags = bytes[20..24];
            ServerChallenge = bytes[24..32];
            Reserved = bytes[32..40];
            TargetInfoLen = bytes[40..42];
            TargetInfoMaxLen = bytes[42..44];
            TargetInfoBufferOffset = bytes[44..48];
            ProductMajorVersion = bytes[48];
            ProductMinorVersion = bytes[49];
            ProductBuild = bytes[50..52];
            VersionReserved = bytes[52..55];
            NTLMRevisionCurrent = bytes[55];
            Payload = bytes[56..];

            SignatureString = Encoding.UTF8.GetString(Signature);
            PayloadString = Encoding.UTF8.GetString(Payload);

            Console.WriteLine("Signature: " + BitConverter.ToString(Signature));
            Console.WriteLine("Signature String: " + SignatureString);
            Console.WriteLine("MessageType: " + BitConverter.ToString(MessageType));
            Console.WriteLine("TargetNameLen: " + BitConverter.ToInt16(TargetNameLen));
            Console.WriteLine("TargetNameMaxLen: " + BitConverter.ToInt16(TargetNameMaxLen));
            Console.WriteLine("TargetNameBufferOffset: " + BitConverter.ToInt32(TargetNameBufferOffset));
            Console.WriteLine("Flags: " + BitConverter.ToString(Flags));
            Console.WriteLine("Server Challenge: " + BitConverter.ToString(ServerChallenge));
            Console.WriteLine("Reserved: " + BitConverter.ToString(Reserved));
            Console.WriteLine("TargetInfoLen: " + BitConverter.ToInt16(TargetInfoLen));
            Console.WriteLine("TargetInfoMaxLen: " + BitConverter.ToInt16(TargetInfoMaxLen));
            Console.WriteLine("TargetInfoBufferOffset: " + BitConverter.ToInt32(TargetInfoBufferOffset));
            Console.WriteLine("Product Major Version: " + Convert.ToInt32(ProductMajorVersion));
            Console.WriteLine("Product Minor Version: " + Convert.ToInt32(ProductMinorVersion));
            Console.WriteLine("Product Build: " + BitConverter.ToInt16(ProductBuild));
            Console.WriteLine("Version Reserved: " + BitConverter.ToString(VersionReserved));
            Console.WriteLine("NTLM Revision Current: " + Convert.ToInt32(NTLMRevisionCurrent));
            Console.WriteLine("Payload: " + BitConverter.ToString(Payload));
            Console.WriteLine("Payload String: " + PayloadString);

            ProcessPayload(Payload);

            Console.WriteLine("Amount of pairs: " + AV_Pairs.Count);
            for(int i = 0;i < AV_Pairs.Count; i++)
            {
                Console.WriteLine('\n');
                Console.WriteLine(BitConverter.ToString(AV_Pairs[i].AvId) + " " + GetTextAVPairId(AV_Pairs[i].AvId));
                Console.WriteLine(BitConverter.ToString(AV_Pairs[i].AV_Len));
                if(AV_Pairs[i].Value != null)
                    Console.WriteLine(Encoding.UTF8.GetString(AV_Pairs[i].Value));
            }
        }

        private byte[] WholeMessage;

        private byte[] Signature = new byte[8];
        private byte[] MessageType = new byte[4];

        private byte[] TargetNameLen = new byte[2];
        private byte[] TargetNameMaxLen = new byte[2];
        private byte[] TargetNameBufferOffset = new byte[4];

        private byte[] Flags = new byte[4];
        private byte[] ServerChallenge = new byte[8];
        private byte[] Reserved = new byte[8];

        private byte[] TargetInfoLen = new byte[2];
        private byte[] TargetInfoMaxLen = new byte[2];
        private byte[] TargetInfoBufferOffset = new byte[4];

        byte ProductMajorVersion;
        byte ProductMinorVersion;
        byte[] ProductBuild = new byte[2];
        byte[] VersionReserved = new byte[3];
        byte NTLMRevisionCurrent;

        private byte[] Payload;

        private string SignatureString = string.Empty;
        private string PayloadString = string.Empty;

        private List<AV_Pair> AV_Pairs = new List<AV_Pair>();



        public string GetTargetName()
        {
            UnicodeEncoding unicodeEncoding = new UnicodeEncoding();

            int Start = BitConverter.ToInt32(TargetNameBufferOffset);
            int End = Start + Convert.ToInt32(BitConverter.ToInt16(TargetNameLen));

            string TargetName = unicodeEncoding.GetString(WholeMessage[Start..End]);
            return TargetName;
        }

        public byte[] GetBytes()
        {
            return WholeMessage;
        }

        public List<AV_Pair> GetTargetBlock()
        {
            return AV_Pairs;
        }

        public byte[] GetServerChallenge()
        {
            return ServerChallenge;
        }

        public byte[] GetFlags()
        {
            return Flags;
        }

        private void ProcessPayload(byte[] payload)
        {
            int index = BitConverter.ToInt16(TargetNameLen);
            while(index < payload.Length)
            {
                AV_Pair pair = new AV_Pair();
                pair.AvId = payload[index..(index + 2)];
                index += 2;
                pair.AV_Len = payload[index..(index + 2)];
                index += 2;
                var end = index + BitConverter.ToUInt16(pair.AV_Len);
                if (end != index)
                {
                    pair.Value = payload[index..end];
                    index = end;
                }
                AV_Pairs.Add(pair);
            }
        }

        private string GetTextAVPairId(byte[] bytes)
        {
            if (bytes[0] == 0x02 )
                return "Netbios domain name";
            else if (bytes[0] == 0x01 )
                return "Netbios computer name";
            else if (bytes[0] == 0x04 )
                return "DNS domain name";
            else if (bytes[0] ==  0x03)
                return "DNS computer name";
            else if (bytes[0] == 0x07 )
                return "Timestamp";
            else
                return "End of list";
        }
    }

    public class NTLM_Authenticate_Message
    {
        private string password;
        private byte[] NTLMv2_Hash = new byte[16];
        private byte[] SessionKey = new byte[16];

        public NTLM_Authenticate_Message(NTLM_Negotiate_Message negotiateMessage,NTLM_Challenge_Message challengeMessage,string Username,string Domain,string Workstation,string Password,bool IsLocalAuthentication)
        {
            password = Password;
            NegotiateBytes = negotiateMessage.GetBytes();
            ChallengeBytes = challengeMessage.GetBytes();

            UnicodeEncoding unicode = new UnicodeEncoding();

            WholeMessage.AddRange(Signature);
            WholeMessage.AddRange(MessageType);

            byte[] ClientNonce = new byte[8];
            Random random = new Random();
            for (int i = 0; i < ClientNonce.Length; i++)
            {
                ClientNonce[i] = (byte)random.Next(0, 255);
            }


            if(IsLocalAuthentication)
            {
                //LM_Challenge = CalcResponse(CreateLMHashedPasswordv1(Password), ServerChallenge);
                LM_Challenge = CreateLMv2Response(Password, challengeMessage.GetTargetName(), ClientNonce, challengeMessage.GetServerChallenge());
                LmChallengeResponseLen = BitConverter.GetBytes(Convert.ToInt16(0));
                LmChallengeResponseMaxLen = BitConverter.GetBytes(Convert.ToInt16(0));
                LmChallengeResponseBufferOffset = BitConverter.GetBytes(88);
            }
            else
            {
                LM_Challenge = CreateLMv2Response(Password, challengeMessage.GetTargetName(), ClientNonce, challengeMessage.GetServerChallenge());
                LmChallengeResponseLen = BitConverter.GetBytes(Convert.ToInt16(LM_Challenge.Length));
                LmChallengeResponseMaxLen = BitConverter.GetBytes(Convert.ToInt16(LM_Challenge.Length));
                LmChallengeResponseBufferOffset = BitConverter.GetBytes(88);
            }

            WholeMessage.AddRange(LmChallengeResponseLen);
            WholeMessage.AddRange(LmChallengeResponseMaxLen);
            WholeMessage.AddRange(LmChallengeResponseBufferOffset);

            if (IsLocalAuthentication)
            {
                //NT_Challenge = CalcResponse(CreateNTHashedPasswordv1(Password), ServerChallenge);
                NT_Challenge = CreateNTLMv2Response(Password, Username, challengeMessage.GetTargetName(), ClientNonce,challengeMessage.GetTargetBlock(), challengeMessage.GetServerChallenge());
                NtChallengeResponseLen = BitConverter.GetBytes(Convert.ToInt16(0));
                NtChallengeResponseMaxLen = BitConverter.GetBytes(Convert.ToInt16(0));
                NtChallengeResponseBufferOffset = BitConverter.GetBytes(88);
            }
            else
            {
                NT_Challenge = CreateNTLMv2Response(Password, Username, challengeMessage.GetTargetName(), ClientNonce, challengeMessage.GetTargetBlock(), challengeMessage.GetServerChallenge());
                NtChallengeResponseLen = BitConverter.GetBytes(Convert.ToInt16(NT_Challenge.Length));
                NtChallengeResponseMaxLen = BitConverter.GetBytes(Convert.ToInt16(NT_Challenge.Length));
                NtChallengeResponseBufferOffset = BitConverter.GetBytes(88 + LM_Challenge.Length);
            }

            WholeMessage.AddRange(NtChallengeResponseLen);
            WholeMessage.AddRange(NtChallengeResponseMaxLen);
            WholeMessage.AddRange(NtChallengeResponseBufferOffset);

            if(IsLocalAuthentication)
            {
                DomainNameLen = BitConverter.GetBytes(Convert.ToInt16(0));
                DomainNameMaxLen = BitConverter.GetBytes(Convert.ToInt16(0));
                DomainNameBufferOffset = BitConverter.GetBytes(88);
            }
            else
            {
                DomainNameBytes = unicode.GetBytes(Domain);
                DomainNameLen = BitConverter.GetBytes(Convert.ToInt16(DomainNameBytes.Length));
                DomainNameMaxLen = BitConverter.GetBytes(Convert.ToInt16(DomainNameBytes.Length));
                DomainNameBufferOffset = BitConverter.GetBytes(88 + LM_Challenge.Length + NT_Challenge.Length);
            }

            WholeMessage.AddRange(DomainNameLen);
            WholeMessage.AddRange(DomainNameMaxLen);
            WholeMessage.AddRange(DomainNameBufferOffset);

            if(IsLocalAuthentication)
            {
                UserNameLen = BitConverter.GetBytes(Convert.ToInt16(0));
                UserNameMaxLen = BitConverter.GetBytes(Convert.ToInt16(0));
                UserNameBufferOffset = BitConverter.GetBytes(88);
            }
            else
            {
                UsernameBytes = unicode.GetBytes(Username);
                UserNameLen = BitConverter.GetBytes(Convert.ToInt16(UsernameBytes.Length));
                UserNameMaxLen = BitConverter.GetBytes(Convert.ToInt16(UsernameBytes.Length));
                UserNameBufferOffset = BitConverter.GetBytes(88 + LM_Challenge.Length + NT_Challenge.Length + DomainNameBytes.Length);
            }

            WholeMessage.AddRange(UserNameLen);
            WholeMessage.AddRange(UserNameMaxLen);
            WholeMessage.AddRange(UserNameBufferOffset);


            if(IsLocalAuthentication)
            {
                WorkstationLen = BitConverter.GetBytes(Convert.ToInt16(0));
                WorkstationMaxLen = BitConverter.GetBytes(Convert.ToInt16(0));
                WorkstationBufferOffset = BitConverter.GetBytes(88);
            }
            else
            {
                WorkstationBytes = unicode.GetBytes(Workstation);
                WorkstationLen = BitConverter.GetBytes(Convert.ToInt16(WorkstationBytes.Length));
                WorkstationMaxLen = BitConverter.GetBytes(Convert.ToInt16(WorkstationBytes.Length));
                WorkstationBufferOffset = BitConverter.GetBytes(88 + LM_Challenge.Length + NT_Challenge.Length + DomainNameBytes.Length + UsernameBytes.Length);
            }

            WholeMessage.AddRange(WorkstationLen);
            WholeMessage.AddRange(WorkstationMaxLen);
            WholeMessage.AddRange(WorkstationBufferOffset);


            if(IsLocalAuthentication)
            {
                EncryptedRandomSessionKeyBufferOffset = BitConverter.GetBytes(88);
            }
            else
            {
                EncryptedRandomSessionKeyBufferOffset = BitConverter.GetBytes(88 + LM_Challenge.Length + NT_Challenge.Length + DomainNameBytes.Length + UsernameBytes.Length + WorkstationBytes.Length);
            }

            WholeMessage.AddRange(EncryptedRandomSessionKeyLen);
            WholeMessage.AddRange(EncryptedRandomSessionKeyMaxLen);
            WholeMessage.AddRange(EncryptedRandomSessionKeyBufferOffset);

            Flags = challengeMessage.GetFlags();
            GenerateVersion();

            WholeMessage.AddRange(Flags);
            WholeMessage.AddRange(Version);

            var newList = new List<byte>(WholeMessage);
            newList.AddRange(new byte[16]);
            AuthenticateBytes = newList.ToArray();

            MIC = CalculateNTLMv2Mic(challengeMessage.GetServerChallenge());
            //MIC = GenerateMic();
            WholeMessage.AddRange(MIC);

            if (!IsLocalAuthentication)
            {
                WholeMessage.AddRange(LM_Challenge);
                WholeMessage.AddRange(NT_Challenge);
                WholeMessage.AddRange(DomainNameBytes);
                WholeMessage.AddRange(UsernameBytes);
                WholeMessage.AddRange(WorkstationBytes);
                WholeMessage.AddRange(EncryptedRandomSessionKeyBytes);
            }
        }
        
        public string GetWholeMessage()
        {
            return Convert.ToBase64String(WholeMessage.ToArray());
        }

        private byte[] NegotiateBytes;
        private byte[] ChallengeBytes;
        private byte[] AuthenticateBytes;

        private List<byte> WholeMessage = new List<byte>();

        private byte[] Signature = new byte[8] { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00 };  //'N' 'T' 'L' 'M' 'S' 'S' 'P' '\0'
        private byte[] MessageType = new byte[4] { 0x03, 0x00, 0x00, 0x00 };

        private byte[] LmChallengeResponseLen = new byte[2];
        private byte[] LmChallengeResponseMaxLen = new byte[2];
        private byte[] LmChallengeResponseBufferOffset = new byte[4];

        private byte[] NtChallengeResponseLen = new byte[2];
        private byte[] NtChallengeResponseMaxLen = new byte[2];
        private byte[] NtChallengeResponseBufferOffset = new byte[4];

        private byte[] DomainNameLen = new byte[2];
        private byte[] DomainNameMaxLen = new byte[2];
        private byte[] DomainNameBufferOffset = new byte[4];

        private byte[] UserNameLen = new byte[2];
        private byte[] UserNameMaxLen = new byte[2];
        private byte[] UserNameBufferOffset = new byte[4];

        private byte[] WorkstationLen = new byte[2];
        private byte[] WorkstationMaxLen = new byte[2];
        private byte[] WorkstationBufferOffset = new byte[4];

        private byte[] EncryptedRandomSessionKeyLen = new byte[2];
        private byte[] EncryptedRandomSessionKeyMaxLen = new byte[2];
        private byte[] EncryptedRandomSessionKeyBufferOffset = new byte[4];

        private byte[] Flags = new byte[4];
        private byte[] Version = new byte[8];
        private byte[] MIC = new byte[16];

        private byte[] LM_Challenge;
        private byte[] NT_Challenge;
        private byte[] DomainNameBytes;
        private byte[] UsernameBytes;
        private byte[] WorkstationBytes;
        private byte[] EncryptedRandomSessionKeyBytes = new byte[0];

        private void GenerateVersion()
        {
            byte ProductMajorVersion = 0x0A;
            byte ProductMinorVersion = 0x00;
            byte[] ProductBuild = new byte[2] { 0x61, 0x4a };
            byte[] Reserved = new byte[3];
            byte NTLMRevisionCurrent = 0x0F;

            List<byte> versionBytes = new List<byte>();
            versionBytes.Add(ProductMajorVersion);
            versionBytes.Add(ProductMinorVersion);
            versionBytes.AddRange(ProductBuild);
            versionBytes.AddRange(Reserved);
            versionBytes.Add(NTLMRevisionCurrent);
            this.Version = versionBytes.ToArray();
        }

        private byte[] CreateNTHashedPasswordv1(string password)
        {
            Org.BouncyCastle.Crypto.Digests.MD4Digest md = new Org.BouncyCastle.Crypto.Digests.MD4Digest();
            byte[] unicodePassword = Encoding.Convert(Encoding.ASCII, Encoding.Unicode, Encoding.ASCII.GetBytes(password));
            md.BlockUpdate(unicodePassword, 0, unicodePassword.Length);
            byte[] hash = new byte[16];
            md.DoFinal(hash, 0);
            string ntlm = BitConverter.ToString(hash);
            return hash;
        }

        private byte[] CreateLMHashedPasswordv1(string password)
        {
            string UpperPassword = password.ToUpper();
            byte[] passwordBytes = Encoding.ASCII.GetBytes(UpperPassword);
            byte[] PaddedBytes = new byte[14];
            passwordBytes.CopyTo(PaddedBytes, 0);


            byte[] firstPart = PaddedBytes[0..7];
            byte[] secondPart = PaddedBytes[7..14];

            byte[] key1 = InsertZerosEvery7Bit(firstPart);
            byte[] key2 = InsertZerosEvery7Bit(secondPart);

            byte[] encryptedFirstPart = DesEncrypt(Encoding.ASCII.GetBytes("KGS!@#$%"), key1);
            byte[] encryptedSecondPart = DesEncrypt(Encoding.ASCII.GetBytes("KGS!@#$%"),key2);

            byte[] result = new byte[16];
            encryptedFirstPart.CopyTo(result, 0);
            encryptedSecondPart.CopyTo(result, 8);

            string hashString = BitConverter.ToString(result);
            return result;
        }

        private byte[] CreateLMv2Response(string password,string Target,byte[] ClientNonce,byte[] serverChallenge)
        {
            //Step 1
            byte[] ntlm_hash = CreateNTHashedPasswordv1(password);

            //Step 2
            string UpperUsername = password.ToUpper();
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] UnicodeUsernameTarget = unicode.GetBytes(UpperUsername + Target);
            HMACMD5 hasher = new HMACMD5();
            hasher.Key = ntlm_hash;
            byte[] ntlmv2_hash = hasher.ComputeHash(UnicodeUsernameTarget);
            ntlmv2_hash.CopyTo(NTLMv2_Hash,0);

            hasher.Key = ntlmv2_hash;

            //Step 4
            List<byte> ChallengeNonce = new List<byte>();
            ChallengeNonce.AddRange(serverChallenge);
            ChallengeNonce.AddRange(ClientNonce);
            byte[] hash = hasher.ComputeHash(ChallengeNonce.ToArray());

            //Step 5
            List<byte> LMv2_Response = new List<byte>(hash);
            LMv2_Response.AddRange(ClientNonce);
            return LMv2_Response.ToArray();      
        }

        private byte[] CreateNTLMv2Response(string password, string Username, string Target, byte[] ClientNonce, List<AV_Pair> targetBlock, byte[] ServerChallenge)
        {
            byte[] BlobSignature = new byte[] { 0x01, 0x01, 0x00, 0x00 };
            byte[] TimeStamp;
            byte[] Unknown = new byte[4];
            byte[] TargetBlock;

            //Step 1
            byte[] ntlm_hash = CreateNTHashedPasswordv1(password);

            //Step 2
            string UpperCaseUsername = Username.ToUpper();
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] UsernameTarget = unicode.GetBytes(UpperCaseUsername + Target);
            HMACMD5 hasher = new HMACMD5();
            hasher.Key = ntlm_hash;
            byte[] ntlmv2_hash = hasher.ComputeHash(UsernameTarget);

            //Step 3
            long time = DateTimeOffset.Now.ToUnixTimeMilliseconds() + 11644473600000L;
            time *= 10000;
            byte[] time_bytes = BitConverter.GetBytes(time);
            TimeStamp = time_bytes;

            //Adding Flags AV_Pair
            AV_Pair FlagsAV_Pair = new AV_Pair() { AvId = new byte[] { 0x06, 0x00 }, AV_Len = new byte[] { 0x04, 0x00 }, Value = new byte[] { 0x02, 0x00, 0x00, 0x00 } };
            targetBlock.Insert(targetBlock.Count - 1, FlagsAV_Pair);

            //Adding Target Name AV_Pair
            string targetName = "HTTP/192.168.1.45:5000";
            byte[] targetNameBytes = unicode.GetBytes(targetName);
            short targetNameBytesLength = Convert.ToInt16(targetNameBytes.Length);
            AV_Pair TargetNameAV_Pair = new AV_Pair() { AvId = new byte[2] { 0x09, 0x00 }, AV_Len = BitConverter.GetBytes(targetNameBytesLength), Value = targetNameBytes  };

            targetBlock.Insert(targetBlock.Count - 1, TargetNameAV_Pair);
            TargetBlock = AV_Pair.ToByteArray(targetBlock);



            List<byte> temp = new List<byte>();
            temp.AddRange(ServerChallenge);
            temp.AddRange(BlobSignature);
            temp.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });
            temp.AddRange(TimeStamp);
            temp.AddRange(ClientNonce);
            temp.AddRange(Unknown);
            temp.AddRange(TargetBlock);
            temp.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            hasher.Key = ntlmv2_hash;
            byte[] NtProof = hasher.ComputeHash(temp.ToArray());

            //Setting Session Key
            SessionKey = hasher.ComputeHash(NtProof);

            List<byte> Blob = new List<byte>();
            Blob.AddRange(NtProof);
            Blob.AddRange(BlobSignature);
            Blob.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });
            Blob.AddRange(TimeStamp);
            Blob.AddRange(ClientNonce);
            Blob.AddRange(Unknown);
            Blob.AddRange(TargetBlock);
            Blob.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });
            return Blob.ToArray();
        }

        private byte[] CalculateNTLMv2Mic(byte[] ServerChallenge)
        {
            #region
            //HMACMD5 hasher = new HMACMD5();
            //hasher.Key = NTLMv2_Hash;

            //List<byte> Resp_Challenge = new List<byte>();
            //Resp_Challenge.AddRange(NT_Challenge);
            //Resp_Challenge.AddRange(ServerChallenge);
            //byte[] FirstPart = hasher.ComputeHash(Resp_Challenge.ToArray());

            //// byte[] SecondPart = hasher.ComputeHash(FirstPart);
            ///
            #endregion

            HMACMD5 hasher = new HMACMD5();
            hasher.Key = SessionKey;

            var AllMessages = new List<byte>();
            AllMessages.AddRange(NegotiateBytes);
            AllMessages.AddRange(ChallengeBytes);
            AllMessages.AddRange(AuthenticateBytes);
            byte[] MIC = hasher.ComputeHash(AllMessages.ToArray());
            return MIC;
        }

        public byte[] InsertZerosEvery7Bit(byte[] array)
        {
            string Seven_Bytes = BitConverter.ToString(array);

            #region
            BitArray Reversed = new BitArray(array);
            BitArray bitArray = new BitArray(Reversed.Length);
            int index = 0;

            for (int i = Reversed.Length - 1; i >= 0; i--)
            {
                bitArray[index] = Reversed[i];
                index += 1;
            }

            var test = new byte[7];
            bitArray.CopyTo(test, 0);
            var test2 = new byte[7];

            index = 0;
            for (int i = test.Length - 1; i >= 0; i--)
            {
                test2[index] = test[i];
                index += 1;
            }

            BitArray bitArray3 = new BitArray(test2);
            BitArray bitArray2 = new BitArray(bitArray.Length + 8);
            bitArray = bitArray3;
            #endregion

            //BitArray bitArray = new BitArray(array);
            //BitArray bitArray2 = new BitArray(bitArray.Length + 8);

            int sourceIndex = 0;
            int ResultIndex = 0;
            int counter = 0;

            while(sourceIndex < bitArray.Length)
            {
                if (counter == 7)
                {
                    bitArray2[ResultIndex] = false;
                    counter = 0;
                    ResultIndex += 1;
                }
                else
                {
                    bitArray2[ResultIndex] = bitArray[sourceIndex];
                    ResultIndex += 1;
                    sourceIndex += 1;
                    counter += 1;
                }
            }


            byte[] result = new byte[8];
            bitArray2.CopyTo(result, 0);

            #region
            var result2 = new byte[result.Length];
            index = 0;
            for (int i = result.Length - 1; i >= 0; i--)
            {
                result2[index] = result[i];
                index += 1;
            }

            BitArray test5 = new BitArray(result2);
            BitArray test6 = new BitArray(test5.Length);
            index = 0;
            for (int i = test5.Length - 1; i >= 0; i--)
            {
                test6[index] = test5[i];
                index += 1;
            }

            byte[] ResultResult = new byte[8];
            test6.CopyTo(ResultResult, 0);
            #endregion

            string Eight_Bytes = BitConverter.ToString(ResultResult);
            return ResultResult;
        }

        private byte[] CreateNTLMv1Response(byte[] password_hash, byte[] server_challenge)
        {
            byte[] PasswordHashPadded = new byte[21];
            password_hash.CopyTo(PasswordHashPadded, 0);

            byte[] firstKey = new byte[7];
            byte[] secondKey = new byte[7];
            byte[] thirdKey = new byte[7];

            firstKey = PasswordHashPadded[0..7];
            secondKey = PasswordHashPadded[7..14];
            thirdKey = PasswordHashPadded[14..21];

            byte[] firstKeyWith7Bits = InsertZerosEvery7Bit(firstKey);
            byte[] secondKeyWith7Bits = InsertZerosEvery7Bit(secondKey);
            byte[] thirdKeyWith7Bits = InsertZerosEvery7Bit(thirdKey);

            List<byte> resultList = new List<byte>();
            resultList.AddRange(DesEncrypt(server_challenge, firstKeyWith7Bits));
            resultList.AddRange(DesEncrypt(server_challenge, secondKeyWith7Bits));
            resultList.AddRange(DesEncrypt(server_challenge, thirdKeyWith7Bits));
            return resultList.ToArray();
        }

        private byte[] DesEncrypt(byte[] input,byte[] key)
        {
            string str = BitConverter.ToString(input);
            string key_str = BitConverter.ToString(key);

            var desEngine = new DesEngine();
            var cbcBlockCipher = new CbcBlockCipher(desEngine);
            var bufferedBlockCipher = new BufferedBlockCipher(cbcBlockCipher);         
            bufferedBlockCipher.Init(true,new ParametersWithIV(new KeyParameter(key),new byte[8]));
            byte[] output = new byte[input.Length];
            bufferedBlockCipher.DoFinal(input, output, 0);

            string output_str = BitConverter.ToString(output);
            return output;
        }

        private byte[] GenerateMic()
        {
            var NT_Hash = CreateNTHashedPasswordv1(password);
            Org.BouncyCastle.Crypto.Digests.MD4Digest md = new Org.BouncyCastle.Crypto.Digests.MD4Digest();
            md.BlockUpdate(NT_Hash, 0, NT_Hash.Length);
            byte[] SessionKey = new byte[16];
            md.DoFinal(SessionKey, 0);

            string SessionKeyString = BitConverter.ToString(SessionKey);
            //byte[] SessionKey = CreateNTHashedPasswordv1(Encoding.UTF8.GetString(CreateNTHashedPasswordv1(password)));

            HMACMD5 hasher = new HMACMD5(SessionKey);

            var AllMessages = new List<byte>();
            AllMessages.AddRange(NegotiateBytes);
            AllMessages.AddRange(ChallengeBytes);
            AllMessages.AddRange(AuthenticateBytes);
            byte[] MIC = hasher.ComputeHash(AllMessages.ToArray());
            return MIC;
        }
    }

    public class AV_Pair
    {
        public byte[] AvId = new byte[2];
        public byte[] AV_Len = new byte[2];
        public byte[] Value;

        public static byte[] ToByteArray(List<AV_Pair> aV_Pairs)
        {
            List<byte> bytes = new List<byte>();
            for(int i = 0;i < aV_Pairs.Count;i++)
            {
                bytes.Add(aV_Pairs[i].AvId[0]);
                bytes.Add(aV_Pairs[i].AvId[1]);

                bytes.Add(aV_Pairs[i].AV_Len[0]);
                bytes.Add(aV_Pairs[i].AV_Len[1]);

                if (aV_Pairs[i].Value != null)
                {
                    for (int j = 0; j < aV_Pairs[i].Value.Length; j++)
                    {
                        bytes.Add(aV_Pairs[i].Value[j]);
                    }
                }
            }

            return bytes.ToArray();
        }
    }

}
