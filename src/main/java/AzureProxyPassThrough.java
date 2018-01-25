package main.java;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.AzureResponseBuilder;
import com.microsoft.azure.Page;
import com.microsoft.azure.PagedList;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.network.Network;
import com.microsoft.azure.management.network.PublicIPAddress;
import com.microsoft.azure.management.network.TransportProtocol;
import com.microsoft.azure.management.resources.ResourceGroup;
import com.microsoft.azure.management.resources.ResourceGroups;
import com.microsoft.azure.management.resources.fluentcore.utils.ProviderRegistrationInterceptor;
import com.microsoft.azure.management.resources.fluentcore.utils.ResourceManagerThrottlingInterceptor;
import com.microsoft.azure.serializer.AzureJacksonAdapter;
import com.microsoft.rest.RestClient;

import okhttp3.OkHttpClient;
import retrofit2.Retrofit;

public class AzureProxyPassThrough {

    public static void stopIfNeeded(int currentStep, int limitStep) {
        if (currentStep >= limitStep) {
            System.exit(0);
        }
    }

    public static void curlUrl(String urlString) {
        URL url = null;
        try {
            url = new URL(urlString);
            BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream(), "UTF-8"));
            for (String line; (line = reader.readLine()) != null; ) {
                System.out.println(line);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void test1(String credFilePath) {
        File activeeon_creds = new File(credFilePath);
        Azure azure = null;
        try {
            azure = Azure.authenticate(activeeon_creds).withDefaultSubscription();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(azure.subscriptionId());
    }

    public static void test2(int limitStep, String credFilePath, String rgGroupName, String regionName) {
        File activeeon_creds = new File(credFilePath);
        Azure azure;
        int currentStep = 0;
        try {

            azure = Azure.authenticate(activeeon_creds).withDefaultSubscription();
            System.out.println("[" + currentStep + "] sessionid:" + azure.subscriptionId());
            stopIfNeeded(++currentStep, limitStep);

            ResourceGroups resourceGroups = azure.resourceGroups();
            System.out.println("[" + currentStep + "] get resources groups: ");
            PagedList<ResourceGroup> pagedList = resourceGroups.list();
            pagedList.loadAll();
            for (ResourceGroup resourceGroup : pagedList.currentPage().items()) {
                System.out.println("    - " + resourceGroup.name() + " (" + resourceGroup.regionName() + ")");
            }
            stopIfNeeded(++currentStep, limitStep);

            resourceGroups.define(rgGroupName).withRegion(regionName).create();
            System.out.println("[" + currentStep + "] created resource group " + rgGroupName);
            stopIfNeeded(++currentStep, limitStep);

            String networkName = rgGroupName + "Network";
            Network network = azure.networks().define(networkName).withRegion(regionName)
                    .withExistingResourceGroup(rgGroupName).withAddressSpace("10.1.0.0/16")
                    .withSubnet("default", "10.1.0.0/16").create();
            System.out.println("[" + currentStep + "] created network " + networkName);
            stopIfNeeded(++currentStep, limitStep);

            String pubIPName = rgGroupName + "PubIP";
            PublicIPAddress publicIPAddress = azure.publicIPAddresses().define(pubIPName)
                    .withRegion(regionName).withExistingResourceGroup(rgGroupName).create();
            System.out.println("[" + currentStep + "] created public ip " + pubIPName);
            stopIfNeeded(++currentStep, limitStep);

            String LBName = rgGroupName + "LB";
            azure.loadBalancers().define(LBName).withRegion(regionName)
                    .withExistingResourceGroup(rgGroupName).defineLoadBalancingRule(LBName)
                    .withProtocol(TransportProtocol.TCP).fromFrontend(LBName).fromFrontendPort(64738)
                    .toBackend("pnp").toBackendPort(64738).attach()
                    .definePublicFrontend(LBName).withExistingPublicIPAddress(publicIPAddress)
                    .attach().create();
            System.out.println("[" + currentStep + "] created LB " + LBName);
            stopIfNeeded(++currentStep, limitStep);


        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void testWith(Azure azure, String rgGroupName, String regionName) {
        int currentStep = 0;
        System.out.println("[" + currentStep + "] sessionid:" + azure.subscriptionId());

        ResourceGroups resourceGroups = azure.resourceGroups();
        System.out.println("[" + currentStep + "] get resources groups: ");
        PagedList<ResourceGroup> pagedList = resourceGroups.list();
        pagedList.loadAll();
        for (ResourceGroup resourceGroup : pagedList.currentPage().items()) {
            System.out.println("    - " + resourceGroup.name() + " (" + resourceGroup.regionName() + ")");
        }

        resourceGroups.define(rgGroupName).withRegion(regionName).create();
        System.out.println("[" + currentStep + "] created resource group " + rgGroupName);

        String networkName = rgGroupName + "Network";
        Network network = azure.networks().define(networkName).withRegion(regionName)
                .withExistingResourceGroup(rgGroupName).withAddressSpace("10.1.0.0/16")
                .withSubnet("default", "10.1.0.0/16").create();
        System.out.println("[" + currentStep + "] created network " + networkName);

        String pubIPName = rgGroupName + "PubIP";
        PublicIPAddress publicIPAddress = azure.publicIPAddresses().define(pubIPName)
                .withRegion(regionName).withExistingResourceGroup(rgGroupName).create();
        System.out.println("[" + currentStep + "] created public ip " + pubIPName);

        String LBName = rgGroupName + "LB";
        azure.loadBalancers().define(LBName).withRegion(regionName)
                .withExistingResourceGroup(rgGroupName).defineLoadBalancingRule(LBName)
                .withProtocol(TransportProtocol.TCP).fromFrontend(LBName).fromFrontendPort(64738)
                .toBackend("pnp").toBackendPort(64738).attach()
                .definePublicFrontend(LBName).withExistingPublicIPAddress(publicIPAddress)
                .attach().create();
        System.out.println("[" + currentStep + "] created LB " + LBName);

    }

    public static void test3(String credFile, String rgGroupName, String regionName) {
        File activeeon_creds = new File(credFile);
        Azure azure = null;
        try {
            ApplicationTokenCredentials credentials = ApplicationTokenCredentials.fromFile(activeeon_creds);

            OkHttpClient.Builder httpClientBuilder = new OkHttpClient.Builder();
            httpClientBuilder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String s, SSLSession sslSession) {
                    return true;
                }
            });
            SSLSocketFactory sslSocketFactory = new SSLSocketFactory() {
                @Override
                public String[] getDefaultCipherSuites() {
                    return new String[0];
                }

                @Override
                public String[] getSupportedCipherSuites() {
                    return new String[0];
                }

                @Override
                public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException {
                    return null;
                }

                @Override
                public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
                    return null;
                }

                @Override
                public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
                    return null;
                }

                @Override
                public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
                    return null;
                }

                @Override
                public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
                    return null;
                }
            };
            X509TrustManager x509TrustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            httpClientBuilder.sslSocketFactory(sslSocketFactory, x509TrustManager);

            Retrofit.Builder retrofitBuilder = new Retrofit.Builder();
            RestClient restClient = new RestClient.Builder(httpClientBuilder, retrofitBuilder)
                    .withBaseUrl(credentials.environment(), AzureEnvironment.Endpoint.RESOURCE_MANAGER)
                    .withCredentials(credentials)
                    .withSerializerAdapter(new AzureJacksonAdapter())
                    .withResponseBuilderFactory(new AzureResponseBuilder.Factory())
                    .withInterceptor(new ProviderRegistrationInterceptor(credentials))
                    .withInterceptor(new ResourceManagerThrottlingInterceptor()).build();
            azure = Azure.authenticate(restClient, credentials.domain()).withDefaultSubscription();
            testWith(azure, rgGroupName, regionName);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(azure);
    }


    public static void main(String[] args) {
        //String pathParaita = "/home/paraita/Bureau/support/CNES/azure_scaleset_activeeon.creds";
        int step = Integer.valueOf(args[0]);
        String credFilePath = args[1];
        String rgGroupName = args[2];
        String regionName = args[3];
        String proxyHost = args[4];
        String proxyPort = args[5];
        String proxyUser = args[6];
        String proxyPassword = args[7];
        //String url = args[8];

        Authenticator.setDefault(
                new Authenticator() {
                    @Override
                    public PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(proxyUser, proxyPassword.toCharArray());
                    }
                }
        );

        System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");

        // HTTP
        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", proxyPort);
        System.setProperty("http.proxyUser", proxyUser);
        System.setProperty("http.proxyPassword", proxyPassword);

        // HTTPS
        System.setProperty("https.proxyHost", proxyHost);
        System.setProperty("https.proxyPort", proxyPort);
        System.setProperty("https.proxyUser", proxyUser);
        System.setProperty("https.proxyPassword", proxyPassword);

        //curlUrl(url);
        test2(step, credFilePath, rgGroupName, regionName);
//        test3(credFilePath, rgGroupName, regionName);
    }
}
