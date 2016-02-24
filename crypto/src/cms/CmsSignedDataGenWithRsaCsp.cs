using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;

namespace Org.BouncyCastle.src.cms
{
    public class CMSSignedDataGenWithRsaCsp : CmsSignedGenerator
    {
        private static readonly CmsSignedHelper Helper = CmsSignedHelper.Instance;
        private readonly ArrayList signerInfs = new ArrayList();

        public CMSSignedDataGenWithRsaCsp()
        {
        }

        public CMSSignedDataGenWithRsaCsp(SecureRandom rand)
            : base(rand)
        {
        }

        public void AddSigner(RSACryptoServiceProvider crProv, X509Certificate cert, string digestOID)
        {
            this.AddSigner(crProv, cert, this.GetEncOid(crProv, digestOID), digestOID);
        }

        public void AddSigner(RSACryptoServiceProvider crProv, X509Certificate cert, string encryptionOID, string digestOID)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, crProv, (AsymmetricKeyParameter)null, CmsSignedGenerator.GetSignerIdentifier(cert), digestOID, encryptionOID, (CmsAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(), (CmsAttributeTableGenerator)null, (Org.BouncyCastle.Asn1.Cms.AttributeTable)null));
        }

        public void AddSigner(RSACryptoServiceProvider crProv, byte[] subjectKeyID, string encryptionOID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, crProv, (AsymmetricKeyParameter)null, CmsSignedGenerator.GetSignerIdentifier(subjectKeyID), digestOID, encryptionOID, signedAttrGen, unsignedAttrGen, (Org.BouncyCastle.Asn1.Cms.AttributeTable)null));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID)
        {
            this.AddSigner(privateKey, cert, this.GetEncOid(privateKey, digestOID), digestOID);
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID, string digestOID)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, (RSACryptoServiceProvider)null, privateKey, CmsSignedGenerator.GetSignerIdentifier(cert), digestOID, encryptionOID, (CmsAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(), (CmsAttributeTableGenerator)null, (Org.BouncyCastle.Asn1.Cms.AttributeTable)null));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID)
        {
            this.AddSigner(privateKey, subjectKeyID, this.GetEncOid(privateKey, digestOID), digestOID);
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID, string digestOID)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, (RSACryptoServiceProvider)null, privateKey, CmsSignedGenerator.GetSignerIdentifier(subjectKeyID), digestOID, encryptionOID, (CmsAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(), (CmsAttributeTableGenerator)null, (Org.BouncyCastle.Asn1.Cms.AttributeTable)null));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
        {
            this.AddSigner(privateKey, cert, GetEncOid(privateKey, digestOID), digestOID, signedAttr, unsignedAttr);
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, (RSACryptoServiceProvider)null, privateKey, CmsSignedGenerator.GetSignerIdentifier(cert), digestOID, encryptionOID, (CmsAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(signedAttr), (CmsAttributeTableGenerator)new SimpleAttributeTableGenerator(unsignedAttr), signedAttr));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
        {
            this.AddSigner(privateKey, subjectKeyID, digestOID, this.GetEncOid(privateKey, digestOID), (CmsAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(signedAttr), (CmsAttributeTableGenerator)new SimpleAttributeTableGenerator(unsignedAttr));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, (RSACryptoServiceProvider)null, privateKey, CmsSignedGenerator.GetSignerIdentifier(subjectKeyID), digestOID, encryptionOID, (CmsAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(signedAttr), (CmsAttributeTableGenerator)new SimpleAttributeTableGenerator(unsignedAttr), signedAttr));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            this.AddSigner(privateKey, cert, this.GetEncOid(privateKey, digestOID), digestOID, signedAttrGen, unsignedAttrGen);
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, (RSACryptoServiceProvider)null, privateKey, CmsSignedGenerator.GetSignerIdentifier(cert), digestOID, encryptionOID, signedAttrGen, unsignedAttrGen, (Org.BouncyCastle.Asn1.Cms.AttributeTable)null));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            this.AddSigner(privateKey, subjectKeyID, digestOID, this.GetEncOid(privateKey, digestOID), signedAttrGen, unsignedAttrGen);
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, (RSACryptoServiceProvider)null, privateKey, CmsSignedGenerator.GetSignerIdentifier(subjectKeyID), digestOID, encryptionOID, signedAttrGen, unsignedAttrGen, (Org.BouncyCastle.Asn1.Cms.AttributeTable)null));
        }

        public void MyAddSigner(RSACryptoServiceProvider crProv, X509Certificate cert, AsymmetricKeyParameter akey, string encryptionOID, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
        {
            this.signerInfs.Add((object)new CMSSignedDataGenWithRsaCsp.SignerInf((CmsSignedGenerator)this, crProv, akey, CmsSignedGenerator.GetSignerIdentifier(cert), digestOID, encryptionOID, (CmsAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(signedAttr), (CmsAttributeTableGenerator)new SimpleAttributeTableGenerator(unsignedAttr), (Org.BouncyCastle.Asn1.Cms.AttributeTable)null));
        }

        /// <summary>
        /// Copied from other <see cref="GetEncOid"/> because it did not compile with methods using <see cref="AsymmetricKeyParameter"/>
        /// </summary>
        /// <param name="crProv"></param>
        /// <param name="digestOID"></param>
        /// <returns></returns>
        protected string GetEncOid(AsymmetricKeyParameter crProv, string digestOID)
        {
            string str = (string)null;
            if (crProv != null)
            {
                if (!crProv.IsPrivate)
                    throw new ArgumentException("Expected private key");
                str = CmsSignedGenerator.EncryptionRsa;

            }
            return str;
        }

        protected string GetEncOid(RSACryptoServiceProvider crProv, string digestOID)
        {
            string str = (string)null;
            if (crProv != null)
            {
                if (crProv.PublicOnly)
                    throw new ArgumentException("Expected RSA private key");
                str = CmsSignedGenerator.EncryptionRsa;
            }
            return str;
        }

        public CmsSignedData Generate(CmsProcessable content)
        {
            return this.Generate(content, false);
        }

        public CmsSignedData Generate(string signedContentType, CmsProcessable content, bool encapsulate)
        {
            Asn1EncodableVector v1 = new Asn1EncodableVector(new Asn1Encodable[0]);
            Asn1EncodableVector v2 = new Asn1EncodableVector(new Asn1Encodable[0]);
            this._digests.Clear();
            foreach (SignerInformation signerInformation in (IEnumerable)this._signers)
            {
                v1.Add((Asn1Encodable)CMSSignedDataGenWithRsaCsp.Helper.FixAlgID(signerInformation.DigestAlgorithmID));
                v2.Add((Asn1Encodable)signerInformation.ToSignerInfo());
            }
            bool isCounterSignature = signedContentType == null;
            DerObjectIdentifier contentType = isCounterSignature ? CmsObjectIdentifiers.Data : new DerObjectIdentifier(signedContentType);
            foreach (CMSSignedDataGenWithRsaCsp.SignerInf signerInf in this.signerInfs)
            {
                try
                {
                    v1.Add((Asn1Encodable)signerInf.DigestAlgorithmID);
                    v2.Add((Asn1Encodable)signerInf.ToSignerInfo(contentType, content, this.rand, isCounterSignature));
                }
                catch (IOException ex)
                {
                    throw new CmsException("encoding error.", (Exception)ex);
                }
                catch (InvalidKeyException ex)
                {
                    throw new CmsException("key inappropriate for signature.", (Exception)ex);
                }
                catch (SignatureException ex)
                {
                    throw new CmsException("error creating signature.", (Exception)ex);
                }
                catch (CertificateEncodingException ex)
                {
                    throw new CmsException("error creating sid.", (Exception)ex);
                }
            }
            Asn1Set certificates = (Asn1Set)null;
            if (this._certs.Count != 0)
                certificates = CmsUtilities.CreateBerSetFromList(this._certs);
            Asn1Set crls = (Asn1Set)null;
            if (this._crls.Count != 0)
                crls = CmsUtilities.CreateBerSetFromList(this._crls);
            Asn1OctetString asn1OctetString = (Asn1OctetString)null;
            if (encapsulate)
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    if (content != null)
                    {
                        try
                        {
                            content.Write(memoryStream);
                        }
                        catch (IOException ex)
                        {
                            throw new CmsException("encapsulation error.", (Exception)ex);
                        }
                    }
                    asn1OctetString = (Asn1OctetString)new BerOctetString(memoryStream.ToArray());
                }
            }
            ContentInfo contentInfo = new ContentInfo(contentType, (Asn1Encodable)asn1OctetString);
            SignedData signedData = new SignedData((Asn1Set)new DerSet(v1), contentInfo, certificates, crls, (Asn1Set)new DerSet(v2));
            ContentInfo sigData = new ContentInfo(CmsObjectIdentifiers.SignedData, (Asn1Encodable)signedData);
            return new CmsSignedData(content, sigData);
        }

        public CmsSignedData Generate(CmsProcessable content, bool encapsulate)
        {
            return this.Generate(CmsSignedGenerator.Data, content, encapsulate);
        }

        public SignerInformationStore GenerateCounterSigners(SignerInformation signer)
        {
            return this.Generate((string)null, (CmsProcessable)new CmsProcessableByteArray(signer.GetSignature()), false).GetSignerInfos();
        }

        public static bool arrAreEquals(byte[] a, byte[] b)
        {
            bool flag = true;
            if (a.Length != b.Length)
                return false;
            for (int index = 0; index < a.Length; ++index)
            {
                if ((int)a[index] != (int)b[index])
                    return false;
            }
            return flag;
        }

        private class SignerInf
        {
            private readonly CmsSignedGenerator outer;
            private readonly AsymmetricKeyParameter key;
            private readonly RSACryptoServiceProvider krProv;
            private readonly SignerIdentifier signerIdentifier;
            private readonly string digestOID;
            private readonly string encOID;
            private readonly CmsAttributeTableGenerator sAttr;
            private readonly CmsAttributeTableGenerator unsAttr;
            private readonly Org.BouncyCastle.Asn1.Cms.AttributeTable baseSignedTable;

            internal AlgorithmIdentifier DigestAlgorithmID
            {
                get
                {
                    return new AlgorithmIdentifier(new DerObjectIdentifier(this.digestOID), (Asn1Encodable)DerNull.Instance);
                }
            }

            internal CmsAttributeTableGenerator SignedAttributes
            {
                get
                {
                    return this.sAttr;
                }
            }

            internal CmsAttributeTableGenerator UnsignedAttributes
            {
                get
                {
                    return this.unsAttr;
                }
            }

            internal SignerInf(CmsSignedGenerator outer, RSACryptoServiceProvider krProv, AsymmetricKeyParameter key, SignerIdentifier signerIdentifier, string digestOID, string encOID, CmsAttributeTableGenerator sAttr, CmsAttributeTableGenerator unsAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable baseSignedTable)
            {
                this.outer = outer;
                this.key = key;
                this.krProv = krProv;
                this.signerIdentifier = signerIdentifier;
                this.digestOID = digestOID;
                this.encOID = encOID;
                this.sAttr = sAttr;
                this.unsAttr = unsAttr;
                this.baseSignedTable = baseSignedTable;
            }

            internal SignerInfo ToSignerInfo(DerObjectIdentifier contentType, CmsProcessable content, SecureRandom random, bool isCounterSignature)
            {
                AlgorithmIdentifier digestAlgorithmId = this.DigestAlgorithmID;
                string digestAlgName = CMSSignedDataGenWithRsaCsp.Helper.GetDigestAlgName(this.digestOID);
                IDigest digestInstance1 = CMSSignedDataGenWithRsaCsp.Helper.GetDigestInstance(digestAlgName);
                string algorithm = digestAlgName + "with" + CMSSignedDataGenWithRsaCsp.Helper.GetEncryptionAlgName(this.encOID);
                if (content != null)
                    content.Write((Stream)new DigOutputStream(digestInstance1));
                byte[] hash = DigestUtilities.DoFinal(digestInstance1);
                this.outer._digests.Add((object)this.digestOID, hash.Clone());
                Asn1Set authenticatedAttributes = (Asn1Set)null;
                byte[] input;
                if (this.sAttr != null)
                {
                    Org.BouncyCastle.Asn1.Cms.AttributeTable attr = this.sAttr.GetAttributes(this.outer.GetBaseParameters(contentType, digestAlgorithmId, hash));
                    if (isCounterSignature)
                    {
                        IDictionary attrs = attr.ToDictionary();
                        attrs.Remove((object)CmsAttributes.ContentType);
                        attr = new Org.BouncyCastle.Asn1.Cms.AttributeTable(attrs);
                    }
                    authenticatedAttributes = this.outer.GetAttributeSet(attr);
                    input = authenticatedAttributes.GetEncoded("DER");
                }
                else
                {
                    MemoryStream memoryStream = new MemoryStream();
                    if (content != null)
                        content.Write((Stream)memoryStream);
                    input = memoryStream.ToArray();
                }
                byte[] str;
                if (this.krProv != null)
                {
                    IDigest digestInstance2 = CMSSignedDataGenWithRsaCsp.Helper.GetDigestInstance(digestAlgName);
                    digestInstance2.BlockUpdate(input, 0, input.Length);
                    byte[] numArray = new byte[digestInstance2.GetDigestSize()];
                    digestInstance2.DoFinal(numArray, 0);
                    str = this.krProv.SignHash(numArray, this.digestOID);
                }
                else
                {
                    ISigner signatureInstance = CMSSignedDataGenWithRsaCsp.Helper.GetSignatureInstance(algorithm);
                    signatureInstance.Init(true, (ICipherParameters)new ParametersWithRandom((ICipherParameters)this.key, random));
                    signatureInstance.BlockUpdate(input, 0, input.Length);
                    str = signatureInstance.GenerateSignature();
                }
                Asn1Set unauthenticatedAttributes = (Asn1Set)null;
                if (this.unsAttr != null)
                {
                    IDictionary baseParameters = this.outer.GetBaseParameters(contentType, digestAlgorithmId, hash);
                    baseParameters[(object)CmsAttributeTableParameter.Signature] = str.Clone();
                    unauthenticatedAttributes = this.outer.GetAttributeSet(this.unsAttr.GetAttributes(baseParameters));
                }
                AlgorithmIdentifier algorithmIdentifier = Helper.GetEncAlgorithmIdentifier(new DerObjectIdentifier(this.encOID), SignerUtilities.GetDefaultX509Parameters(algorithm));
                return new SignerInfo(this.signerIdentifier, digestAlgorithmId, authenticatedAttributes, algorithmIdentifier, (Asn1OctetString)new DerOctetString(str), unauthenticatedAttributes);
            }
        }
    }
}
