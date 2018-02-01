package main.java;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import com.microsoft.aad.adal4j.AuthenticationCallback;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.AzureResponseBuilder;
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
import com.microsoft.rest.LogLevel;
import com.microsoft.rest.RestClient;

import okhttp3.OkHttpClient;
import retrofit2.Retrofit;

public class AzureProxyPassThrough {

    public static Map<String, String> getParams(String[] args) {
        Map<String, String> params = new HashMap<String, String>();
        params.put("proxyHost", args[1]);
        params.put("proxyPort", args[2]);
        params.put("proxyUser", args[3]);
        params.put("proxyPassword", args[4]);

        switch (args[0]) {
            case "test1":
            case "test2":
            case "test3":
            case "test4":
                params.put("credFilePath", args[5]);
                params.put("rgGroupName", args[6]);
                params.put("regionName", args[7]);
                break;
            case "test5":
                params.put("tenantId", args[5]);
                params.put("clientId", args[6]);
                params.put("password", args[7]);
                break;
            case "test6":
                params.put("credFilePath", args[5]);
                break;
            default:
                break;
        }
        return params;
    }

    public static void setProxy(Map<String, String> params) {
        Authenticator.setDefault(
                new Authenticator() {
                    @Override
                    public PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(params.get("proxyUser"),
                                params.get("proxyPassword").toCharArray());
                    }
                }
        );

        System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
        System.setProperty("com.sun.net.ssl.checkRevocation", "false");

        // HTTP
        System.setProperty("http.proxyHost", params.get("proxyHost"));
        System.setProperty("http.proxyPort", params.get("proxyPort"));
        System.setProperty("http.proxyUser", params.get("proxyUser"));
        System.setProperty("http.proxyPassword", params.get("proxyPassword"));

        // HTTPS
        System.setProperty("https.proxyHost", params.get("proxyHost"));
        System.setProperty("https.proxyPort", params.get("proxyPort"));
        System.setProperty("https.proxyUser", params.get("proxyUser"));
        System.setProperty("https.proxyPassword", params.get("proxyPassword"));
    }

    public static void stopIfNeeded(int currentStep, int limitStep) {
        if (currentStep >= limitStep) {
            System.exit(0);
        }
    }

    public static void testWith(Azure azure, Map<String, String> params) {
        int currentStep = 0;
        System.out.println("[" + currentStep + "] sessionid:" + azure.subscriptionId());

        ResourceGroups resourceGroups = azure.resourceGroups();
        System.out.println("[" + currentStep + "] get resources groups: ");
        PagedList<ResourceGroup> pagedList = resourceGroups.list();
        pagedList.loadAll();
        for (ResourceGroup resourceGroup : pagedList.currentPage().items()) {
            System.out.println("    - " + resourceGroup.name() + " (" + resourceGroup.regionName() + ")");
        }

        resourceGroups.define(params.get("rgGroupName")).withRegion(params.get("regionName")).create();
        System.out.println("[" + currentStep + "] created resource group " + params.get("rgGroupName"));

        String networkName = params.get("rgGroupName") + "Network";
        Network network = azure.networks().define(networkName).withRegion(params.get("regionName"))
                .withExistingResourceGroup(params.get("rgGroupName")).withAddressSpace("10.1.0.0/16")
                .withSubnet("default", "10.1.0.0/16").create();
        System.out.println("[" + currentStep + "] created network " + networkName);

        String pubIPName = params.get("rgGroupName") + "PubIP";
        PublicIPAddress publicIPAddress = azure.publicIPAddresses().define(pubIPName)
                .withRegion(params.get("regionName")).withExistingResourceGroup(params.get("rgGroupName")).create();
        System.out.println("[" + currentStep + "] created public ip " + pubIPName);

        String LBName = params.get("rgGroupName") + "LB";
        azure.loadBalancers().define(LBName).withRegion(params.get("regionName"))
                .withExistingResourceGroup(params.get("rgGroupName")).defineLoadBalancingRule(LBName)
                .withProtocol(TransportProtocol.TCP).fromFrontend(LBName).fromFrontendPort(64738)
                .toBackend("pnp").toBackendPort(64738).attach()
                .definePublicFrontend(LBName).withExistingPublicIPAddress(publicIPAddress)
                .attach().create();
        System.out.println("[" + currentStep + "] created LB " + LBName);

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

    public static void test1(Map<String, String> params) {
        File activeeon_creds = new File(params.get("credFilePath"));
        Azure azure = null;
        try {
            azure = Azure.authenticate(activeeon_creds).withDefaultSubscription();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(azure.subscriptionId());
    }

    public static void test2(Map<String, String> params) {
        String credFilePath = params.get("credFilePath");
        String rgGroupName = params.get("rgGroupName");
        String regionName = params.get("regionName");
        File activeeon_creds = new File(credFilePath);
        Azure azure;
        int currentStep = 0;
        try {

            azure = Azure.authenticate(activeeon_creds).withDefaultSubscription();
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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void test3(Map<String, String> params) {

        File activeeon_creds = new File(params.get("credFilePath"));

        Azure azure = null;
        try {
            ApplicationTokenCredentials credentials = ApplicationTokenCredentials.fromFile(activeeon_creds);

            OkHttpClient.Builder httpClientBuilder = new OkHttpClient.Builder();
            httpClientBuilder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String s, SSLSession sslSession) {
                    System.out.println("Bypassing the hostname verification");
                    return true;
                }
            });
            SSLContext sslContext = SSLContext.getInstance("SSL");
            X509TrustManager[] x509TrustManager = new X509TrustManager[] {
                    new X509TrustManager() {
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
                    }
            };
            sslContext.init(null, x509TrustManager, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            httpClientBuilder.sslSocketFactory(sslSocketFactory, x509TrustManager[0]);

            Retrofit.Builder retrofitBuilder = new Retrofit.Builder();
            RestClient restClient = new RestClient.Builder(httpClientBuilder, retrofitBuilder)
                    .withBaseUrl(credentials.environment(), AzureEnvironment.Endpoint.RESOURCE_MANAGER)
                    .withCredentials(credentials)
                    .withSerializerAdapter(new AzureJacksonAdapter())
                    .withResponseBuilderFactory(new AzureResponseBuilder.Factory())
                    .withInterceptor(new ProviderRegistrationInterceptor(credentials))
                    .withInterceptor(new ResourceManagerThrottlingInterceptor())
                    //.withReadTimeout(60, TimeUnit.SECONDS)
//                    .withProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(params.get("proxyHost"), Integer.valueOf(params.get("proxyPort")))))
//                    .withProxyAuthenticator(new okhttp3.Authenticator() {
//                        @Override
//                        public Request authenticate(Route route, Response response) throws IOException {
//                            return null;
//                        }
//                    })
                    .build();

            azure = Azure
                    .configure()
                    .withLogLevel(LogLevel.BODY_AND_HEADERS)
                    .authenticate(credentials)
//                    .authenticate(restClient, credentials.domain())
                    .withDefaultSubscription();
            testWith(azure, params);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        System.out.println(azure);
    }

    public static void test4(Map<String, String> params) {
        System.out.println("Running test4:");
        File activeeon_creds = new File(params.get("credFilePath"));

        Azure azure = null;
        try {
            ApplicationTokenCredentials credentials = ApplicationTokenCredentials.fromFile(activeeon_creds);
            azure = Azure.authenticate(credentials).withDefaultSubscription();
            String bearerToken = credentials.getToken("https://management.azure.com/");
            System.out.println("Recuperation du Token Bearer: " + bearerToken);
            HttpClient client = HttpClientBuilder.create().build();
            System.out.println("Recuperation de la liste des resources groups:");
            HttpGet request = new HttpGet("https://management.azure.com/subscriptions/3b73c31c-7e58-4d66-940b-84905c8b2559/resourcegroups?api-version=2017-05-10");
            request.addHeader("Authorization", "Bearer " + bearerToken);
            HttpResponse response = client.execute(request);
            System.out.println(response.getStatusLine());
            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

            StringBuffer result = new StringBuffer();
            String line = "";
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }
            System.out.println(result);

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void test5(Map<String, String> params) {
        System.out.println("Running test5:");
        String tenantId = params.get("tenantId");
        String clientId = params.get("clientId");
        String password = params.get("password");
        AuthenticationContext authContext = null;
        AuthenticationResult authResult = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            String url = "https://login.microsoftonline.com/" + tenantId + "/oauth2/authorize";
            System.out.println("Authentication to " + url);
            authContext = new AuthenticationContext(url, false, service);
            ClientCredential clientCredential = new ClientCredential(clientId, password);
            Future<AuthenticationResult> future =  authContext.acquireToken("https://management.azure.com",
                    clientCredential, new AuthenticationCallback() {
                @Override
                public void onSuccess(AuthenticationResult result) {
                    System.out.println("Token acquired ! " + result.getAccessToken());
                }

                @Override
                public void onFailure(Throwable exc) {
                    System.out.println("Token acquisition failed ! ");
                    exc.printStackTrace();
                }
            });
            authResult = future.get();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            service.shutdown();
        }

    }

    public static void test6(Map<String, String> params) {
        System.out.println("Running test6 with more logs:");
        File activeeon_creds = new File(params.get("credFilePath"));

        Azure azure = null;
        try {
            ApplicationTokenCredentials credentials = ApplicationTokenCredentials.fromFile(activeeon_creds);
            Azure.Authenticated authenticated = Azure
                    .configure()
                    .withLogLevel(LogLevel.BODY_AND_HEADERS)
                    .authenticate(credentials);
            System.out.println("Authenticated using tenantId [" + authenticated.tenantId() + "]");
            System.out.println("Configuring to subscription [" + credentials.defaultSubscriptionId() + "]");
            azure = authenticated.withSubscription(credentials.defaultSubscriptionId());
//            azure = authenticated.withDefaultSubscription();
            System.out.println("Authentication/configuration succeeded");
            System.out.println("Listing the resources groups:");
            PagedList<ResourceGroup> rgList = azure.resourceGroups().list();
            rgList.loadAll();
            for (ResourceGroup resourceGroup: rgList.currentPage().items()) {
                System.out.println("    - " + resourceGroup.name() + "(" + resourceGroup.regionName() + ")");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    public static void main(String[] args) {
        //String pathParaita = "/home/paraita/Bureau/support/CNES/azure_scaleset_activeeon.creds";

        String testToRun = args[0];
        Map<String, String> params = getParams(args);
        setProxy(params);

        switch (testToRun) {
            case "curlUrl":
                curlUrl("https://www.activeeon.com");
            case "test1":
                test1(params);
                break;
            case "test2":
                test2(params);
                break;
            case "test3":
                test3(params);
                break;
            case "test4":
                test4(params);
                break;
            case "test5":
                test5(params);
                break;
            case "test6":
                test6(params);
                break;
            default:
                System.out.println("Unknown test ! (" + testToRun + ")");
        }
    }
}
