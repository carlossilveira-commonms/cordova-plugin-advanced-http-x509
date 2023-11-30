package com.silkimen.cordovahttp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;


import com.silkimen.http.TLSConfiguration;

import org.apache.cordova.CallbackContext;

import android.app.Activity;
import android.util.Log;
import android.content.res.AssetManager;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

class CordovaServerTrust implements Runnable {
  
  private static final String TAG = "Cordova-Plugin-HTTP";

  private final TrustManager[] noOpTrustManagers;
  private final HostnameVerifier noOpVerifier;

  private String mode;
  private Activity activity;
  private TLSConfiguration tlsConfiguration;
  private CallbackContext callbackContext;

  public CordovaServerTrust(final String mode, final Activity activity, final TLSConfiguration configContainer,
      final CallbackContext callbackContext) {

    this.mode = mode;
    this.activity = activity;
    this.tlsConfiguration = configContainer;
    this.callbackContext = callbackContext;

    TrustManagerFactory tmf = null;
    try {
        tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
    } catch (NoSuchAlgorithmException e) {
        Log.e(TAG, "Error al  obtener TrustManagerFactory", e);
    } catch (KeyStoreException e) {
        Log.e(TAG, "Error al inicializar TrustManagerFactory", e);
    }

    TrustManager[] trustManagers = tmf.getTrustManagers();
    X509TrustManager systemTrustManager = null;

    for (TrustManager trustManager : trustManagers) {
        if (trustManager instanceof X509TrustManager) {
            systemTrustManager = (X509TrustManager) trustManager;
            break;
        }
    }

    if (systemTrustManager == null) {
        throw new IllegalStateException("No X509TrustManager found");
    }

    final X509TrustManager finalTrustManager = systemTrustManager;
    this.noOpTrustManagers = new TrustManager[] { new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
            return finalTrustManager.getAcceptedIssuers();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            finalTrustManager.checkClientTrusted(chain, authType);
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            finalTrustManager.checkServerTrusted(chain, authType);
        }
    } };

    this.noOpVerifier = new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) {
        return true;
      }
    };
  }

  @Override
  public void run() {
    try {
      if ("legacy".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(null);
      } else if ("nocheck".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(this.noOpVerifier);
        this.tlsConfiguration.setTrustManagers(this.noOpTrustManagers);
      } else if ("pinned".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(this.getTrustManagers(this.getCertsFromBundle(getWebAssetDir() + "/certificates")));
      } else {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(this.getTrustManagers(this.getCertsFromKeyStore("AndroidCAStore")));
      }

      callbackContext.success();
    } catch (Exception e) {
      Log.e(TAG, "An error occured while configuring SSL cert mode", e);
      callbackContext.error("An error occured while configuring SSL cert mode");
    }
  }

  private String getWebAssetDir() {
    return isRunningOnCapacitor()? "public" : "www";
  }

  private  boolean isRunningOnCapacitor() {
    return this.activity.getClass().getSuperclass().getName().contains("com.getcapacitor");
  }

  private TrustManager[] getTrustManagers(KeyStore store) throws GeneralSecurityException {
    String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
    tmf.init(store);

    return tmf.getTrustManagers();
  }

  private KeyStore getCertsFromBundle(String path) throws GeneralSecurityException, IOException {
    AssetManager assetManager = this.activity.getAssets();
    String[] files = assetManager.list(path);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    String keyStoreType = KeyStore.getDefaultType();
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);

    keyStore.load(null, null);

    for (int i = 0; i < files.length; i++) {
      int index = files[i].lastIndexOf('.');

      if (index == -1 || !files[i].substring(index).equals(".cer")) {
        continue;
      }

      keyStore.setCertificateEntry("CA" + i, cf.generateCertificate(assetManager.open(path + "/" + files[i])));
    }

    return keyStore;
  }

  private KeyStore getCertsFromKeyStore(String storeType) throws GeneralSecurityException, IOException {
    KeyStore store = KeyStore.getInstance(storeType);
    store.load(null);

    return store;
  }
}
