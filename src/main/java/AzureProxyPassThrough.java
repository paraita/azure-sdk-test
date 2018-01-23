package main.java;

import java.io.File;
import java.io.IOException;

import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.network.Network;
import com.microsoft.azure.management.network.PublicIPAddress;
import com.microsoft.azure.management.network.TransportProtocol;
import com.microsoft.azure.management.resources.fluentcore.arm.Region;

public class AzureProxyPassThrough {

    public static void stopIfNeeded(int currentStep, int limitStep) {
        if (currentStep >= limitStep) {
            System.exit(0);
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
        Azure azure = null;
        int currentStep = 0;
        try {

            azure = Azure.authenticate(activeeon_creds).withDefaultSubscription();
            System.out.println("[" + currentStep + "] sessionid:" + azure.subscriptionId());
            stopIfNeeded(++currentStep, limitStep);

            azure.resourceGroups().define(rgGroupName).withRegion(regionName).create();
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

    //    public static void test2() {
//        File activeeon_creds = new File("/home/paraita/Bureau/support/CNES/azure_scaleset_activeeon.creds");
//        Azure azure = null;
//        try {
////            azure = Azure.authenticate(activeeon_creds).withDefaultSubscription();
//            ApplicationTokenCredentials credentials = ApplicationTokenCredentials.fromFile(activeeon_creds);
//
//            OkHttpClient.Builder httpClientBuilder = new Builder();
//            httpClientBuilder.hostnameVerifier(new HostnameVerifier() {
//                @Override
//                public boolean verify(String s, SSLSession sslSession) {
//                    return true;
//                }
//            });
//            Retrofit retrofitBuilder
//            //RestClient.Builder(httpClientBuilder, retrofitBuilder)
//            azure = Azure.authenticate(restClient, "").withDefaultSubscription();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        System.out.println(azure);
//    }



    public static void main(String[] args) {
        //String pathParaita = "/home/paraita/Bureau/support/CNES/azure_scaleset_activeeon.creds";
        int step = Integer.valueOf(args[0]);
        String credFilePath = args[1];
        String rgGroupName = args[2];
        String regionName = args[3];
        test2(step, credFilePath, rgGroupName, regionName);
    }
}
