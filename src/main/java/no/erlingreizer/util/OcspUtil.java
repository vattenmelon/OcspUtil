package no.erlingreizer.util;


import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import sun.security.x509.X509CertImpl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class OcspUtil {

    public List<X509Certificate> getCertificates(byte[] rawOcspBytes) throws IOException, OCSPException, CertificateException {
        OCSPResp resp = new OCSPResp(rawOcspBytes);
        BasicOCSPResp rs = (BasicOCSPResp) resp.getResponseObject();
        X509CertificateHolder[] certs = rs.getCerts();
        List<X509CertificateHolder> x509CertificateHolders = Arrays.asList(certs);
        List<X509Certificate> certificates = new ArrayList<>();
        for (X509CertificateHolder x50holder : x509CertificateHolders) {
            certificates.add(new X509CertImpl(x50holder.getEncoded()));
        }
        return certificates;

    }
}
