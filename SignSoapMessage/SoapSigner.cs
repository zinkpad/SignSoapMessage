using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SignSoapMessage
{ 
    public enum SignAlgorithm
    {
        SHA1 = 0,
        SHA256 = 1
    }

    public class SoapSigner
    {        
               
        public XmlDocument SignMessage(XmlDocument xmlDoc, X509Certificate2 certificate, SignAlgorithm signAlgorithm)
        {
            XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");

            XmlElement soapHeader = xmlDoc.DocumentElement.SelectSingleNode("//s:Header", ns) as XmlElement;
            XmlElement body = xmlDoc.DocumentElement.SelectSingleNode("//s:Body", ns) as XmlElement;

            if (body == null)
                throw new Exception("No body tag found.");

            XmlElement securityNode = xmlDoc.CreateElement(
                "wsse",
                "Security",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");

            XmlElement binarySecurityToken = xmlDoc.CreateElement("wse", "BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            binarySecurityToken.SetAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            binarySecurityToken.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
            binarySecurityToken.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "BinaryToken1");            

            binarySecurityToken.InnerText = Convert.ToBase64String(certificate.GetRawCertData());

            securityNode.AppendChild(binarySecurityToken);

            soapHeader.AppendChild(securityNode);

            SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);

            if (signAlgorithm == SignAlgorithm.SHA1)
            {
                signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            }
            else
            {
                signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            }

            RSACryptoServiceProvider rsaKey = null;

            if (signAlgorithm == SignAlgorithm.SHA1)
            {
                rsaKey = (RSACryptoServiceProvider)certificate.PrivateKey;
            }
            else
            {
                var key = (RSACryptoServiceProvider)certificate.PrivateKey;
                var enhCsp = new RSACryptoServiceProvider().CspKeyContainerInfo;
                var cspparams = new CspParameters(enhCsp.ProviderType, enhCsp.ProviderName, key.CspKeyContainerInfo.KeyContainerName);
                rsaKey = new RSACryptoServiceProvider(cspparams);            
            }
            
            signedXml.SigningKey = rsaKey;

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new SecurityTokenReference("BinaryToken1"));

            signedXml.KeyInfo = keyInfo;

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            Reference reference = new Reference { Uri = "#_1" };
            if (signAlgorithm == SignAlgorithm.SHA1)
            {
                reference.DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
            }
            else
            {
                reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            }
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();

            XmlElement signedElement = signedXml.GetXml();

            securityNode.AppendChild(signedElement);


            if (soapHeader == null)
            {
                soapHeader = xmlDoc.CreateElement("s:Header", "");
                xmlDoc.DocumentElement.InsertBefore(soapHeader, xmlDoc.DocumentElement.ChildNodes[0]);
            }           

            return xmlDoc;
        }
    }
}
