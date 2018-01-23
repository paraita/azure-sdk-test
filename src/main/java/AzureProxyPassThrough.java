package main.java;

import java.io.File;
import java.io.IOException;

import com.microsoft.azure.management.Azure;

public class AzureProxyPassThrough {

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

    public static void test2(int step, String credFilePath) {
        File activeeon_creds = new File(credFilePath);
        Azure azure = null;
        try {
            azure = Azure.authenticate(activeeon_creds).withDefaultSubscription();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(azure.subscriptionId());
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
        test2(step, credFilePath);
    }
}
