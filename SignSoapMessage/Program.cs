using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SignSoapMessage
{
    class Program
    {
        static void Main(string[] args)
        {
            XmlDocument doc = new XmlDocument();

            doc.Load(@"E:\test\soap_body.xml");

            X509Certificate2 cert = null;

            try
            {
                // Open the store of personal certificates.
                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Sign", "Select certificate", X509SelectionFlag.SingleSelection);

                if (scollection != null && scollection.Count == 1)
                {
                    cert = scollection[0];

                    if (cert.HasPrivateKey == false)
                    {
                        throw new Exception("Certificate has no private key.");
                    }
                }

                store.Close();
            }
            catch (Exception)
            {
                throw new Exception("An error has occurred.");
            }

            SoapMessage message = new SoapMessage();
            message.Certificate = cert;
            message.Body = doc.DocumentElement;
            var result = message.GetXml(true);

            result.Save(@"E:\test\soap_message.xml");
        }
    }
}
