using System;
using System.CommandLine.DragonFruit;
using System.IO;
using System.Security.Cryptography;
using Serilog;
using Newtonsoft.Json;

namespace LicenseGen
{
    class Program
    {
        static int Main(bool GenerateKeyPair=false, bool GenerateLicense=false, bool ValidateLicense =false, FileInfo PrivateKey=null, FileInfo PublicKey=null, FileInfo LicenseFile=null)
        {
            Log.Logger = new LoggerConfiguration().MinimumLevel.Information().WriteTo.Console().CreateLogger();
            Log.Information("LicenseOTC Key Generator");
            if (GenerateKeyPair)
            {
                if (PrivateKey == null)
                {
                    Log.Error("Missing Required Parameters[{missing}]","PRIVATE");
                    return -1;
                }
                if (PublicKey == null)
                {
                    Log.Error("Missing Required Parameters[{missing}]","PUBLIC");
                    return -1;
                }
                RSA _rsa = RSA.Create();
                File.WriteAllBytes(PublicKey.FullName,_rsa.ExportRSAPublicKey());
                File.WriteAllBytes(PrivateKey.FullName,_rsa.ExportRSAPrivateKey());
                Log.Information("New Key Pair Generated and Saved");
                Log.Information("Private Key: {private}",PrivateKey.FullName);
                Log.Information(" Public Key: {public}",PublicKey.FullName);
                return 0;
            }
            else if (GenerateLicense)
            {
                if (PrivateKey == null)
                {
                    Log.Error("Missing Required Parameters[{missing}]","PRIVATE");
                    return -1;
                }
                LicenseOTC.License _license = new LicenseOTC.License();
                while(string.IsNullOrWhiteSpace(_license.Name))
                {
                    Console.Write("      Name: ");
                    _license.Name = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(_license.Name))
                        Log.Error("License Name cannot be empty.");
                }
                while(string.IsNullOrWhiteSpace(_license.Email))
                {
                    Console.Write("      Email: ");
                    _license.Email = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(_license.Email))
                        Log.Error("License Email cannot be empty.");
                }
                while(String.IsNullOrWhiteSpace(_license.Company))
                {
                    Console.Write("   Company: ");
                    _license.Company = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(_license.Company))
                        Log.Error("License Company cannot be empty.");
                }
                while(_license.Expiration.Date <= DateTime.UtcNow)
                {
                    Console.Write("Expiration: ");
                    try {
                        _license.Expiration = Convert.ToDateTime(Console.ReadLine());
                        if (_license.Expiration.Date <= DateTime.UtcNow)
                            Log.Error("License Expiration cannot be before or equal to DateTime.UtcNow.");
                    }
                    catch
                    {
                        Log.Error("License Expiration format specified was invalid or empty.");
                    }
                }
                while (true)
                {
                    Console.Write("      Type: ");
                    object _result;
                    if (Enum.TryParse(typeof(LicenseOTC.LicenseType),Console.ReadLine(),true,out _result))
                    {
                        _license.Type = (LicenseOTC.LicenseType)_result;
                        break;
                    }
                    else 
                        Log.Error("License Type specified was invalid or empty.");
                }
                Console.Write("Would you like to add additional features[yN]: ");
                string _additional = Console.ReadLine();
                while(_additional.ToLower() == "y")
                {
                    Console.Write("  Key: ");
                    string _key = Console.ReadLine();
                    Console.Write("Value: ");
                    string _value = Console.ReadLine();
                    if (String.IsNullOrWhiteSpace(_key))
                    {
                        Console.Write("Would you like to stop adding additional features[Y/N]: ");
                        if (Console.ReadLine().ToLower() == "y")
                            break;
                    }
                    if (!_license.Features.ContainsKey(_key))
                        _license.Features.Add(_key,_value);
                    else
                    {
                        Console.Write("Would you like to overwrite existing feature[Y/N]: ");
                        if (Console.ReadLine().ToLower() == "y")
                            _license.Features[_key] = _value;
                    }
                }
                _license.Sign(new ReadOnlySpan<byte>(File.ReadAllBytes(PrivateKey.FullName)));
                string json_signedLicense = _license.ToString();
                if (LicenseFile == null)
                    Console.WriteLine(json_signedLicense);
                else
                    File.WriteAllText(LicenseFile.FullName,json_signedLicense);

            }
            else if (ValidateLicense)
            {
                if (PublicKey == null)
                {
                    Log.Error("Missing Required Parameters[{missing}]","PUBLIC");
                    return -1;
                }
            }
            return 0;
        }
    }
}
