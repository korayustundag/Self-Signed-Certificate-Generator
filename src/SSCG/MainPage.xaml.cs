using System;
using System.Collections.Generic;
using System.IO;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Windows.UI.Popups;
using System.Text;
using System.IO.Compression;
using Windows.Storage;
using Windows.Storage.Provider;
using Windows.Storage.Pickers;
using System.Collections.ObjectModel;

namespace SSCG
{
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
            Years.Add(1);
            Years.Add(2);
            Years.Add(3);
            yearSelect.SelectedIndex = 0;
        }

        ObservableCollection<int> Years = new ObservableCollection<int>();

        private string GetCert(byte[] crtdata)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN CERTIFICATE-----");
            sb.AppendLine(Convert.ToBase64String(crtdata, Base64FormattingOptions.InsertLineBreaks));
            sb.Append("-----END CERTIFICATE-----");
            return sb.ToString();
        }

        private string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            StringBuilder sb = new StringBuilder();
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    string dt = new string(base64, i, Math.Min(64, base64.Length - i));
                    sb.AppendLine(dt);
                }
                sb.Append("-----END RSA PRIVATE KEY-----");
                return sb.ToString();
            }
        }

        private void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        private string GetKey(RSA rcsp)
        {
            return ExportPrivateKey((RSACryptoServiceProvider)rcsp);
        }

        public byte[] CreateZipFile(string cert, string key)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, true))
                {
                    var crtfile = archive.CreateEntry("Certificate.crt");
                    using (var entryStream = crtfile.Open())
                    {
                        using (var streamWriter = new StreamWriter(entryStream))
                        {
                            streamWriter.Write(cert);
                            streamWriter.Close();
                            streamWriter.Close();
                            entryStream.Close();
                        }
                    }

                    var keyfile = archive.CreateEntry("Certificate.key");
                    using (var entryStream = keyfile.Open())
                    {
                        using (var streamWriter = new StreamWriter(entryStream))
                        {
                            streamWriter.Write(key);
                            streamWriter.Close();
                            streamWriter.Close();
                            entryStream.Close();
                        }
                    }
                }
                return memoryStream.ToArray();
            }
        }

        private async void btnCreate_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtCN.Text))
            {
                MessageDialog mbox = new MessageDialog("Please enter a Common Name!", "Error");
                await mbox.ShowAsync();
                return;
            }
            if (string.IsNullOrWhiteSpace(txtO.Text))
            {
                MessageDialog mbox = new MessageDialog("Please enter a Organization Name!", "Error");
                await mbox.ShowAsync();
                return;
            }
            if (string.IsNullOrWhiteSpace(txtO.Text))
            {
                MessageDialog mbox = new MessageDialog("Please enter a Organization Name!", "Error");
                await mbox.ShowAsync();
                return;
            }
            if (string.IsNullOrWhiteSpace(txtOU.Text))
            {
                MessageDialog mbox = new MessageDialog("Please enter a Organizational Unit Name!", "Error");
                await mbox.ShowAsync();
                return;
            }
            if (string.IsNullOrWhiteSpace(txtL.Text))
            {
                MessageDialog mbox = new MessageDialog("Please enter a Locality Name!", "Error");
                await mbox.ShowAsync();
                return;
            }
            if (string.IsNullOrWhiteSpace(txtS.Text))
            {
                MessageDialog mbox = new MessageDialog("Please enter a State Name!", "Error");
                await mbox.ShowAsync();
                return;
            }
            if (string.IsNullOrWhiteSpace(txtC.Text))
            {
                MessageDialog mbox = new MessageDialog("Please enter a Country Name!", "Error");
                await mbox.ShowAsync();
                return;
            }
            string csr = "CN=" + txtCN.Text + ",O=" + txtO.Text + ",OU=" + txtOU.Text + ",L=" + txtL.Text + ",S=" + txtS.Text + ",C=" + txtC.Text.ToUpper();
            using (RSA rsaKey = new RSACryptoServiceProvider(2048))
            {
                CertificateRequest parentReq = new CertificateRequest(
                    csr,
                    rsaKey,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                parentReq.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));

                parentReq.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

                if ((bool)isSSL.IsChecked)
                {
                    parentReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(OidList.SSL(), false));
                    parentReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                    SubjectAlternativeNameBuilder sab = new SubjectAlternativeNameBuilder();
                    sab.AddDnsName(txtCN.Text);
                    parentReq.CertificateExtensions.Add(sab.Build());
                }
                else
                {
                    parentReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(OidList.CodeSign(), false));
                    parentReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
                }

                using (X509Certificate2 parentCert = parentReq.CreateSelfSigned(DateTimeOffset.UtcNow,DateTimeOffset.UtcNow.AddYears(int.Parse(yearSelect.SelectedItem.ToString()))))
                {
                    if ((bool)isSSL.IsChecked)
                    {
                        byte[] crt = parentCert.Export(X509ContentType.Cert);
                        string crtData = GetCert(crt);
                        string PrivateKey = GetKey(rsaKey);
                        byte[] ZippedBytes = CreateZipFile(crtData, PrivateKey);
                        var savePicker = new FileSavePicker();
                        savePicker.SuggestedStartLocation = PickerLocationId.Desktop;
                        savePicker.FileTypeChoices.Add("Compressed Zip Archive", new List<string>() { ".zip" });
                        savePicker.SuggestedFileName = "Certificate";
                        StorageFile file = await savePicker.PickSaveFileAsync();
                        if (file != null)
                        {
                            CachedFileManager.DeferUpdates(file);
                            await FileIO.WriteBytesAsync(file, ZippedBytes);
                            FileUpdateStatus status = await CachedFileManager.CompleteUpdatesAsync(file);
                            if (status == FileUpdateStatus.Complete)
                            {
                                MessageDialog mbox = new MessageDialog("File " + file.Name + " was saved.", "Info");
                                await mbox.ShowAsync();
                            }
                            else
                            {
                                MessageDialog mbox = new MessageDialog("File " + file.Name + " couldn't be saved.", "Error");
                                await mbox.ShowAsync();
                            }
                        }
                        else
                        {
                            MessageDialog mbox = new MessageDialog("Operation cancelled.", "Info");
                            await mbox.ShowAsync();
                        }

                    }
                    else
                    {
                        byte[] crt = parentCert.Export(X509ContentType.Pfx);
                        var savePicker = new FileSavePicker();
                        savePicker.SuggestedStartLocation = PickerLocationId.Desktop;
                        savePicker.FileTypeChoices.Add("Certificate File", new List<string>() { ".pfx" });
                        savePicker.SuggestedFileName = "Certificate";
                        StorageFile file = await savePicker.PickSaveFileAsync();
                        if (file != null)
                        {
                            CachedFileManager.DeferUpdates(file);
                            await FileIO.WriteBytesAsync(file, crt);
                            FileUpdateStatus status = await CachedFileManager.CompleteUpdatesAsync(file);
                            if (status == FileUpdateStatus.Complete)
                            {
                                MessageDialog mbox = new MessageDialog("File " + file.Name + " was saved.", "Info");
                                await mbox.ShowAsync();
                            }
                            else
                            {
                                MessageDialog mbox = new MessageDialog("File " + file.Name + " couldn't be saved.", "Error");
                                await mbox.ShowAsync();
                            }
                        }
                        else
                        {
                            MessageDialog mbox = new MessageDialog("Operation cancelled.", "Info");
                            await mbox.ShowAsync();
                        }
                    }
                }
            }
        }
    }
}
