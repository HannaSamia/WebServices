namespace DigitalSigningProject.Controllers.Api
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography.Xml;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;

    [Route("api/[controller]")]
    [ApiController]
    public class SigningController : ControllerBase
    {
        [HttpPost("sign")]
        public IActionResult SignXML([FromForm] IFormFile xmlfile, [FromForm] string key)
        {
            CspParameters cspParams;
            RSACryptoServiceProvider rsaKey;

            cspParams = new CspParameters();
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            cspParams.KeyContainerName = key;

            rsaKey = new RSACryptoServiceProvider(1024, cspParams);
            RSACryptoServiceProvider.UseMachineKeyStore = true;

            XmlDocument xmlDoc = new XmlDocument();

            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlfile.OpenReadStream());
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            SignXml(xmlDoc, rsaKey);

            byte[] bytes = Encoding.Default.GetBytes(xmlDoc.OuterXml);

            return File(bytes, "application/force-download", "file.xml");
        }

        public static void SignXml(XmlDocument xmlDoc, RSA rsaKey)
        {
            if (xmlDoc == null)
                throw new ArgumentException(nameof(xmlDoc));
            if (rsaKey == null)
                throw new ArgumentException(nameof(rsaKey));

            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = rsaKey;

            Reference reference = new Reference();
            reference.Uri = "";

            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            signedXml.AddReference(reference);

            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }


        [HttpPost("verifie")]
        public IActionResult VerifieXML([FromForm] IFormFile verfiexmlfile, [FromForm] string verfiekey)
        {
            CspParameters cspParams = new CspParameters();
            cspParams.KeyContainerName = verfiekey;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(1024, cspParams);
            RSACryptoServiceProvider.UseMachineKeyStore = true;

            XmlDocument xmlDoc = new XmlDocument();

            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(verfiexmlfile.OpenReadStream());
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return Ok(VerifyXml(xmlDoc, rsaKey));
        }

        public static string VerifyXml(XmlDocument xmlDoc, RSA key)
        {
            if (xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            if (key == null)
                throw new ArgumentException("key");

            SignedXml signedXml = new SignedXml(xmlDoc);
            XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");

            if (nodeList.Count <= 0)
            {
                return "Verification failed: No Signature was found in the document.";
            }

            if (nodeList.Count >= 2)
            {
                return "Verification failed: More that one signature was found for the document.";
            }

            signedXml.LoadXml((XmlElement)nodeList[0]);

            if (signedXml.CheckSignature(key))
            {
                return "The XML signature is valid.";
            }
            else
            {
                return "The XML signature is not valid.";
            }
        }

        [HttpPost("encrypt")]
        public IActionResult EncryptXMLElement([FromForm] IFormFile xmlfile, [FromForm] string key, [FromForm] string elementName, [FromForm] string elementKey)
        {
            XmlDocument xmlDoc = new XmlDocument();

            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlfile.OpenReadStream());
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            CspParameters cspParams = new CspParameters();
            cspParams.KeyContainerName = key;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(1024, cspParams);
            RSACryptoServiceProvider.UseMachineKeyStore = true;

            try
            {
                Encrypt(xmlDoc, elementName, elementName, rsaKey, elementKey);
                byte[] bytes = Encoding.Default.GetBytes(xmlDoc.OuterXml);

                return File(bytes, "application/force-download", "file.xml");
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
            finally
            {
                rsaKey.Clear();
            }
        }

        public static void Encrypt(XmlDocument Doc, string ElementToEncrypt, string EncryptionElementID, RSA Alg, string KeyName)
        {
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (ElementToEncrypt == null)
                throw new ArgumentNullException("ElementToEncrypt");
            if (EncryptionElementID == null)
                throw new ArgumentNullException("EncryptionElementID");
            if (Alg == null)
                throw new ArgumentNullException("Alg");
            if (KeyName == null)
                throw new ArgumentNullException("KeyName");
            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;

            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");
            }
            Aes sessionKey = null;

            try
            {

                sessionKey = Aes.Create();

                EncryptedXml eXml = new EncryptedXml();

                byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);

                EncryptedData edElement = new EncryptedData();
                edElement.Type = EncryptedXml.XmlEncElementUrl;
                edElement.Id = EncryptionElementID;

                edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
                EncryptedKey ek = new EncryptedKey();

                byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, Alg, false);

                ek.CipherData = new CipherData(encryptedKey);

                ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);

                DataReference dRef = new DataReference();

                dRef.Uri = "#" + EncryptionElementID;

                ek.AddReference(dRef);

                edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

                KeyInfoName kin = new KeyInfoName();

                kin.Value = KeyName;

                ek.KeyInfo.AddClause(kin);

                edElement.CipherData.CipherValue = encryptedElement;

                EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
            }
            catch (Exception e)
            {
                // re-throw the exception.
                throw e;
            }
            finally
            {
                if (sessionKey != null)
                {
                    sessionKey.Clear();
                }
            }
        }


        [HttpPost("decrypt")]
        public IActionResult DecryptXMLElement([FromForm] IFormFile xmlfile, [FromForm] string key, [FromForm] string elementKey)
        {
            XmlDocument xmlDoc = new XmlDocument();

            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlfile.OpenReadStream());
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
            CspParameters cspParams = new CspParameters();
            cspParams.KeyContainerName = key;

            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(1024, cspParams);
            RSACryptoServiceProvider.UseMachineKeyStore = true;

            try
            {
                Decrypt(xmlDoc, rsaKey, elementKey);


                byte[] bytes = Encoding.Default.GetBytes(xmlDoc.OuterXml);
                return File(bytes, "application/force-download", "file.xml");
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
            finally
            {
                rsaKey.Clear();
            }
        }


        public static void Decrypt(XmlDocument Doc, RSA Alg, string KeyName)
        {
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (Alg == null)
                throw new ArgumentNullException("Alg");
            if (KeyName == null)
                throw new ArgumentNullException("KeyName");

            EncryptedXml exml = new EncryptedXml(Doc);
            exml.AddKeyNameMapping(KeyName, Alg);

            exml.DecryptDocument();
        }


        [HttpPost("encrypt/cert")]
        public IActionResult EncryptwithcertXMLElement([FromForm] IFormFile xmlfile, [FromForm] IFormFile certificate, [FromForm] string elementName)
        {
            try
            {
                XmlDocument xmlDoc = new XmlDocument();

                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlfile.OpenReadStream());


                byte[] CertBytes = null;
                if (certificate.Length > 0)
                {
                    using (var ms = new MemoryStream())
                    {
                        certificate.CopyTo(ms);
                        CertBytes = ms.ToArray();
                    }
                }
                X509Certificate2 cert = new X509Certificate2(CertBytes);

                if (cert == null)
                {
                    throw new CryptographicException("The X.509 certificate could not be found.");
                }
 

                // Encrypt the "creditcard" element.
                EncryptWithCert(xmlDoc, elementName, cert);

                // Save the XML document.
                byte[] bytes = Encoding.Default.GetBytes(xmlDoc.OuterXml);

                return File(bytes, "application/force-download", "file.xml");
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        public static void EncryptWithCert(XmlDocument Doc, string ElementToEncrypt, X509Certificate2 Cert)
        {
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (ElementToEncrypt == null)
                throw new ArgumentNullException("ElementToEncrypt");
            if (Cert == null)
                throw new ArgumentNullException("Cert");


            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");
            }

            EncryptedXml eXml = new EncryptedXml();

            EncryptedData edElement = eXml.Encrypt(elementToEncrypt, Cert);

            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
        }

        /// <summary>
        /// Not Working unfortunatly c# doesn't have the ability to decrypt cerftificate unless installed on machine
        /// </summary>
        /// <param name="xmlfile"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        [HttpPost("decrypt/cert")]
        public IActionResult DecryptwithcertXMLElement([FromForm] IFormFile xmlfile, [FromForm] IFormFile certificate)
        {
            try
            {
                XmlDocument xmlDoc = new XmlDocument();

                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlfile.OpenReadStream());

                byte[] CertBytes = null;
                if (certificate.Length > 0)
                {
                    using (var ms = new MemoryStream())
                    {
                        certificate.CopyTo(ms);
                        CertBytes = ms.ToArray();
                    }
                }
                X509Certificate2 cert = new X509Certificate2(CertBytes, "Hanna");


                // Decrypt the document.
                DecryptCert(xmlDoc, cert);

                // Save the XML document.
                byte[] bytes = Encoding.Default.GetBytes(xmlDoc.OuterXml);

                return File(bytes, "application/force-download", "file.xml");
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }

        }
        public static void DecryptCert(XmlDocument Doc, X509Certificate2 cert)
        {
            // Check the arguments.
            if (Doc == null)
                throw new ArgumentNullException("Doc");

            // Create a new EncryptedXml object.
            EncryptedXml exml = new EncryptedXml(Doc);
            exml.AddKeyNameMapping("rsaKey", cert.GetRSAPrivateKey());
            exml.Recipient = "rsaKey";
            // Decrypt the XML document.
            exml.DecryptDocument();
        }
    }
}
