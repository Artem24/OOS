package ru.icm.test;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import ru.CryptoPro.Crypto.CryptoProvider;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.reprov.RevCheck;

import javax.net.ssl.*;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * Created by artem on 07.07.2015.
 */
public class OOSTester {

    private CloseableHttpClient httpclient = null;
    private RequestConfig config = null;
    private static  String boundary = Long.toHexString(System.currentTimeMillis());
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private String ServerResponse = "";

    private String Login;
    private String Pass;
    private String Sign;
    private String Host;

    public static void main(String[] args) throws Exception {

        OOSTester tester = new OOSTester("login", "pass", "", "https://zakupki.gov.ru/pgz/services/upload");
        tester.setProxy("proxy.net", 8080, "proxy_login", "proxy_pass");
        tester.testSend("test");
    }

    public OOSTester(String login, String pass, String sign, String host) {

        Login = login;
        Pass = pass;
        Sign = sign;
        Host = host;

        if (Security.getProvider(CryptoProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new CryptoProvider());
        }

        if (Security.getProvider(JCP.PROVIDER_NAME) == null) {
            Security.addProvider(new JCP());
        }

        if (Security.getProvider(ru.CryptoPro.ssl.Provider.PROVIDER_NAME) == null) {
            Security.addProvider(new ru.CryptoPro.ssl.Provider());
        }
        if (Security.getProvider(RevCheck.PROVIDER_NAME) == null) {
            Security.addProvider(new RevCheck());
        }
    }

    public void testSend(String s) throws Exception {

        HttpPost httppost = new HttpPost(Host);

        if(config == null) {
            initConfig();
        }

        httppost.setConfig(config);

        httppost.setHeader("Cache-Control", "no-cache");
        httppost.setHeader("Connection", "keep-alive");
        httppost.setHeader("User-Agent", "Mozilla/3.0 (compatible; Indy Library)");

        MultipartEntityBuilder entity = MultipartEntityBuilder.create();
        entity.setBoundary(boundary);

        entity.addTextBody("login", Login);
        entity.addTextBody("password", Pass);

        entity.addBinaryBody("document", s.getBytes(), ContentType.TEXT_HTML, "file0.xml");
        entity.addTextBody("signature", Sign);

        httppost.setEntity(entity.build());

        CloseableHttpResponse response = httpclient.execute(httppost);

        HttpEntity resEntity = response.getEntity();

        if (resEntity != null) {
            resEntity.writeTo(baos);
            ServerResponse = baos.toString("Utf-8");
        }

        EntityUtils.consume(resEntity);
        response.close();

        returnSecuritySettingsToDefault();

        String result = "";
        if(response.getStatusLine().getStatusCode() != 200) {
            System.out.print("Server return error status: " + response.getStatusLine());
        } else {
            System.out.print(ServerResponse);
        }
    }

    public void returnSecuritySettingsToDefault() {
        HttpsURLConnection.setDefaultSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault());

        if (Security.getProvider(CryptoProvider.PROVIDER_NAME) != null) {
            Security.removeProvider(CryptoProvider.PROVIDER_NAME);
        }

        if (Security.getProvider(JCP.PROVIDER_NAME) != null) {
            Security.removeProvider(JCP.PROVIDER_NAME);
        }

        if (Security.getProvider(ru.CryptoPro.ssl.Provider.PROVIDER_NAME) != null) {
            Security.removeProvider(ru.CryptoPro.ssl.Provider.PROVIDER_NAME);
        }
        if (Security.getProvider(RevCheck.PROVIDER_NAME) != null) {
            Security.removeProvider(RevCheck.PROVIDER_NAME);
        }
    }

    private static SSLContext getSSLContext() {
        try {
            TrustManager[] trustAllCerts = { new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            } };

            SSLContext sc = SSLContext.getInstance("GostTLS");

            HostnameVerifier hv = new HostnameVerifier() {
                @Override
                public boolean verify(String arg0, SSLSession arg1) {
                    return true;
                }
            };

            sc.init(null, trustAllCerts, new SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(hv);

            return sc;

        } catch (Exception localException) {
            localException.printStackTrace();
        }

        return null;
    }

    private void initConfig() {
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(getSSLContext(),
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);

        httpclient = HttpClients.custom()
                .setSSLSocketFactory(sslsf)
                .build();

        config = RequestConfig.custom()
                .setSocketTimeout(10000)
                .setConnectTimeout(10000)
                .setConnectionRequestTimeout(10000)
                .build();
    }

    public void setProxy(String server, int port, String login, String pass) {
        CredentialsProvider credsProvider;

        if(login == null || (login != null && login.equals(""))){
            credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(
                    new AuthScope(server, port),
                    new UsernamePasswordCredentials(""));
        } else {
            credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(
                    new AuthScope(server, port),
                    new UsernamePasswordCredentials(login, pass));
        }

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(getSSLContext(),
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);

        httpclient = HttpClients.custom()
                .setDefaultCredentialsProvider(credsProvider)
                .setSSLSocketFactory(sslsf)
                .build();

        HttpHost proxy = new HttpHost(server, port);

        config = RequestConfig.custom()
                .setProxy(proxy)
                .setSocketTimeout(10000)
                .setConnectTimeout(10000)
                .setConnectionRequestTimeout(10000)
                .build();
    }


}
