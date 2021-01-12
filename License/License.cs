using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Text;
using CSharpVitamins;
using System.IO;


namespace LicenseOTC
{
    public class License
    {   
        private readonly DateTime _startTime;
        private ShortGuid _id;
        public string Id { get { return _id.ToString(); } set { _id = new ShortGuid(value); }}
        public string Name {get; set;}
        public string Email {get; set;}
        public string Company {get; set;}
        public DateTime Expiration {get; set;}

        [JsonConverter(typeof(StringEnumConverter))]
        public LicenseType Type {get; set;}
        public Dictionary<string,string> Features {get; set;}
        public byte[] Signature {get; set; }
        public bool CheckSignature(ReadOnlySpan<byte> PublicKey)
        {
            RSA _rsa = RSA.Create();
            int _bytesRead = 0;
            _rsa.ImportRSAPublicKey(PublicKey,out _bytesRead);
            License _copy = new License();
            _copy.Id = this.Id;
            _copy.Name = this.Name;
            _copy.Email = this.Email;
            _copy.Company = this.Company;
            _copy.Expiration = this.Expiration;
            _copy.Type = this.Type;
            _copy.Features = this.Features;
            byte[] _licenseBytes = _copy.ToByteArray();
            return _rsa.VerifyData(_licenseBytes,this.Signature,HashAlgorithmName.SHA512,RSASignaturePadding.Pkcs1);

        }
        public bool IsRuntimeExceeded()
        {
            if (this.Type == LicenseType.TRIAL)
            {
                if (DateTime.UtcNow >= (_startTime.AddHours(1)))
                    return true;
            }
            return false;
        }
        public bool IsLicenseExpired()
        {
            if (DateTime.UtcNow >= this.Expiration)
                return true;
            return false;
        }
        public void Sign(ReadOnlySpan<byte> PrivateKey)
        {
            RSA _rsa = RSA.Create();
            int _bytesRead = 0;
            _rsa.ImportRSAPrivateKey(PrivateKey,out _bytesRead);
            if (this.Signature != null || this.Signature.Length > 0)
                this.Signature = new byte[0];
            byte[] _licenseBytes = this.ToByteArray();
            byte[] signed_licenseBytes = _rsa.SignData(_licenseBytes,0,_licenseBytes.Length,HashAlgorithmName.SHA512,RSASignaturePadding.Pkcs1);
            this.Signature = signed_licenseBytes;
        }
        public byte[] ToByteArray()
        {
            return Encoding.Default.GetBytes(JsonConvert.SerializeObject(this,Formatting.None));
        }
        public override string ToString()
        {
            return JsonConvert.SerializeObject(this,Formatting.Indented);
        }
        public License()
        {
            _id = new ShortGuid(Guid.NewGuid());
            Name = string.Empty;
            Email = string.Empty;
            Company = string.Empty;
            Expiration = DateTime.UtcNow;
            Type = LicenseType.TRIAL;
            Signature = new byte[0];
            Features = new Dictionary<string, string>();
            _startTime = DateTime.UtcNow;
        }
        public License(string LicenseFile)
        {
            if (File.Exists(LicenseFile))
            {
                License _load = (License)JsonConvert.DeserializeObject<License>(System.IO.File.ReadAllText(LicenseFile));
                this.Id = _load.Id;
                this.Name = _load.Name;
                this.Email = _load.Email;
                this.Company = _load.Company;
                this.Expiration = _load.Expiration;
                this.Type = _load.Type;
                this.Signature = _load.Signature;
                this.Features = _load.Features;
                _startTime = DateTime.UtcNow;
            }
            else
                throw new FileNotFoundException("Invalid License File Path specified.");
        }
    }
    public enum LicenseType
    {
        STANDARD,
        PROFESSIONAL,
        ENTERPRISE,
        TRIAL
    }
}
