package com.reactlibrary.rnwifi;

import android.content.Context;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.uimanager.IllegalViewOperationException;
import com.reactlibrary.rnwifi.receivers.WifiScanResultReceiver;
import com.reactlibrary.utils.LocationUtils;
import com.reactlibrary.utils.PermissionUtils;
import com.thanosfisherman.wifiutils.WifiUtils;
import com.thanosfisherman.wifiutils.wifiConnect.ConnectionSuccessListener;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

import androidx.annotation.NonNull;

class FailureCodes {
    static int SYSTEM_ADDED_CONFIG_EXISTS = 1;
    static int FAILED_TO_CONNECT = 2;
    static int FAILED_TO_ADD_CONFIG = 3;
    static int FAILED_TO_BIND_CONFIG = 4;
}

public class RNWifiModule extends ReactContextBaseJavaModule {
    private final WifiManager wifi;
    private final WifiManager wifiManager;
    private final ReactApplicationContext context;
    private ConnectivityManager connectivityManager;

    RNWifiModule(ReactApplicationContext context) {
        super(context);

        // TODO: get when needed
        wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        wifiManager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        connectivityManager = (ConnectivityManager) context.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        this.context = context;
    }

    @Override
    public String getName() {
        return "WifiManager";
    }

    /**
     * Returns a list of nearby WiFI networks.
     */
    @ReactMethod
    public void loadWifiList(final Promise promise) {
        try {
            final List<ScanResult> results = wifi.getScanResults();
            final JSONArray wifiArray = new JSONArray();

            for (ScanResult result : results) {
                final JSONObject wifiObject = new JSONObject();
                if (!result.SSID.equals("")) {
                    try {
                        wifiObject.put("SSID", result.SSID);
                        wifiObject.put("BSSID", result.BSSID);
                        wifiObject.put("capabilities", result.capabilities);
                        wifiObject.put("frequency", result.frequency);
                        wifiObject.put("level", result.level);
                        wifiObject.put("timestamp", result.timestamp);
                    } catch (final JSONException jsonException) {
                        promise.reject("jsonException", jsonException.getMessage());
                        return;
                    }
                    wifiArray.put(wifiObject);
                }
            }

            promise.resolve(wifiArray.toString());
        } catch (final IllegalViewOperationException illegalViewOperationException) {
            promise.reject("exception", illegalViewOperationException.getMessage());
        }
    }

    /**
     * Use this to execute api calls to a wifi network that does not have internet access.
     *
     * Useful for commissioning IoT devices.
     *
     * This will route all app network requests to the network (instead of the mobile connection).
     * It is important to disable it again after using as even when the app disconnects from the wifi
     * network it will keep on routing everything to wifi.
     *
     * @param useWifi boolean to force wifi off or on
     */
    @ReactMethod
    public void forceWifiUsage(final boolean useWifi, final Promise promise) {
        final ConnectivityManager connectivityManager = (ConnectivityManager) context
                .getSystemService(Context.CONNECTIVITY_SERVICE);

        if (connectivityManager == null) {
            promise.reject(ForceWifiUsageErrorCodes.couldNotGetConnectivityManager.toString(), "Failed to get the ConnectivityManager.");
            return;
        }

        if (useWifi) {
            NetworkRequest networkRequest = new NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .build();
            connectivityManager.requestNetwork(networkRequest, new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(@NonNull final Network network) {
                    super.onAvailable(network);
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        connectivityManager.bindProcessToNetwork(network);
                    } else {
                        ConnectivityManager.setProcessDefaultNetwork(network);
                    }

                    connectivityManager.unregisterNetworkCallback(this);

                    promise.resolve(null);
                }
            });
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                connectivityManager.bindProcessToNetwork(null);
            } else {
                ConnectivityManager.setProcessDefaultNetwork(null);
            }

            promise.resolve(null);
        }
    }

    /**
     * Method to check if wifi is enabled.
     */
    @ReactMethod
    public void isEnabled(final Promise promise) {
        if (this.wifi == null) {
            promise.reject(IsEnabledErrorCodes.couldNotGetWifiManager.toString(), "Failed to initialize the WifiManager.");
            return;
        }

        promise.resolve(wifi.isWifiEnabled());
    }

    /**
     * Method to set the WiFi on or off on the user's device.
     *
     * @param enabled
     */
    @ReactMethod
    public void setEnabled(final boolean enabled) {
        wifi.setWifiEnabled(enabled);
    }

    /**
     * Use this to connect with a wifi network.
     * Example:  wifi.findAndConnect(ssid, password, false);
     * The promise will resolve with the message 'connected' when the user is connected on Android.
     *
     * @param SSID     name of the network to connect with
     * @param password password of the network to connect with
     * @param isWep    only for iOS
     * @param promise  to send success/error feedback
     */
    @ReactMethod
    public void connectToProtectedSSID(@NonNull final String SSID, @NonNull final String password, final boolean isWep, final Promise promise) {
        final boolean locationPermissionGranted = PermissionUtils.isLocationPermissionGranted(context);
        if (!locationPermissionGranted) {
            promise.reject("location permission missing", "Location permission is not granted");
            return;
        }

        final boolean isLocationOn = LocationUtils.isLocationOn(context);
        if (!isLocationOn) {
            promise.reject("location off", "Location service is turned off");
            return;
        }

        WifiUtils.withContext(context).connectWith(SSID, password).onConnectionResult(new ConnectionSuccessListener() {
            @Override
            public void isSuccessful(boolean isSuccess) {
                if (isSuccess) {
                    promise.resolve("connected");
                } else {
                    promise.reject("failed", "Could not connect to network");
                }
            }
        }).start();
    }

    @ReactMethod
    public void connectSecure(final String ssid, final String passphrase, final Boolean isWEP,
                              final Boolean bindNetwork, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                connectToWifi(ssid, passphrase, isWEP, bindNetwork, callback);
            }
        }).start();
    }

    private WifiConfiguration createWifiConfiguration(String ssid, String passphrase, Boolean isWEP) {
        WifiConfiguration configuration = new WifiConfiguration();
        configuration.SSID = String.format("\"%s\"", ssid);

        if (passphrase.equals("")) {
            configuration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
        } else if (isWEP) {
            configuration.wepKeys[0] = "\"" + passphrase + "\"";
            configuration.wepTxKeyIndex = 0;
            configuration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
            configuration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
        } else { // WPA/WPA2
            configuration.preSharedKey = "\"" + passphrase + "\"";
        }

        if (!wifiManager.isWifiEnabled()) {
            wifiManager.setWifiEnabled(true);
        }
        return configuration;
    }

    private boolean pollForValidSSSID(int maxSeconds, String expectedSSID) {
        try {
            for (int i = 0; i < maxSeconds; i++) {
                String ssid = this.getWifiSSID();
                if (ssid != null && ssid.equalsIgnoreCase(expectedSSID)) {
                    return true;
                }
                Thread.sleep(1000);
            }
        } catch (InterruptedException e) {
            return false;
        }
        return false;
    }

    private void connectToWifi(String ssid, String passphrase, Boolean isWEP, Boolean bindNetwork, Callback callback) {
        if (!removeSSID(ssid)) {
            callback.invoke(errorFromCode(FailureCodes.SYSTEM_ADDED_CONFIG_EXISTS));
            return;
        }

        WifiConfiguration configuration = createWifiConfiguration(ssid, passphrase, isWEP);
        int networkId = wifiManager.addNetwork(configuration);

        if (networkId != -1) {
            // Enable it so that android can connect
            wifiManager.disconnect();
            boolean success =  wifiManager.enableNetwork(networkId, true);
            if (!success) {
                callback.invoke(errorFromCode(FailureCodes.FAILED_TO_ADD_CONFIG));
                return;
            }
            success = wifiManager.reconnect();
            if (!success) {
                callback.invoke(errorFromCode(FailureCodes.FAILED_TO_CONNECT));
                return;
            }
            boolean connected = pollForValidSSSID(10, ssid);
            if (!connected) {
                callback.invoke(errorFromCode(FailureCodes.FAILED_TO_CONNECT));
                return;
            }
            if (!bindNetwork) {
                callback.invoke();
                return;
            }
            try {
                bindToNetwork(ssid, callback);
            } catch (Exception e) {
                Log.d("IoTWifi", "Failed to bind to Wifi: " + ssid);
                callback.invoke();
            }
        } else {
            callback.invoke(errorFromCode(FailureCodes.FAILED_TO_ADD_CONFIG));
        }
    }

    private String errorFromCode(int errorCode) {
        return "ErrorCode: " + errorCode;
    }

    private void bindToNetwork(final String ssid, final Callback callback) {
        NetworkRequest.Builder builder = new NetworkRequest.Builder();
        builder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
        connectivityManager.requestNetwork(builder.build(), new ConnectivityManager.NetworkCallback() {

            private boolean bound = false;

            @Override
            public void onAvailable(Network network) {
                String offeredSSID = getWifiSSID();

                if (!bound && offeredSSID.equals(ssid)) {
                    try {
                        bindProcessToNetwork(network);
                        bound = true;
                        callback.invoke();
                        return;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                callback.invoke(errorFromCode(FailureCodes.FAILED_TO_BIND_CONFIG));
            }

            @Override
            public void onLost(Network network) {
                if (bound) {
                    bindProcessToNetwork(null);
                    connectivityManager.unregisterNetworkCallback(this);
                }
            }
        });
    }
    
    @ReactMethod
    public void removeSSID(String ssid, Boolean unbind, Callback callback) {
        if (!removeSSID(ssid)) {
            callback.invoke(errorFromCode(FailureCodes.SYSTEM_ADDED_CONFIG_EXISTS));
            return;
        }
        if (unbind) {
            bindProcessToNetwork(null);
        }

        callback.invoke();
    }

    private void bindProcessToNetwork(final Network network) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            connectivityManager.bindProcessToNetwork(network);
        } else {
            ConnectivityManager.setProcessDefaultNetwork(network);
        }
    }

    private boolean removeSSID(String ssid) {
        boolean success = true;
        // Remove the existing configuration for this network
        WifiConfiguration existingNetworkConfigForSSID = getExistingNetworkConfig(ssid);

        //No Config found
        if (existingNetworkConfigForSSID == null) {
            return success;
        }
        int existingNetworkId = existingNetworkConfigForSSID.networkId;
        if (existingNetworkId == -1) {
            return success;
        }
        success = wifiManager.removeNetwork(existingNetworkId) && wifiManager.saveConfiguration();
        //If not our config then success would be false
        return success;
    }

    /**
     * Returns if the device is currently connected to a WiFi network.
     */
    @ReactMethod
    public void connectionStatus(final Promise promise) {
        final ConnectivityManager connectivityManager = (ConnectivityManager) getReactApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo wifiInfo = connectivityManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        if (wifiInfo == null) {
            promise.resolve(false);
            return;
        }

        promise.resolve(wifiInfo.isConnected());
    }

    /**
     * Disconnect currently connected WiFi network.
     */
    @ReactMethod
    public void disconnect() {
        wifi.disconnect();
    }

    /**
     * This method will return current SSID
     *
     * @param promise
     */
    @ReactMethod
    public void getCurrentWifiSSID(final Promise promise) {
        WifiInfo info = wifi.getConnectionInfo();

        // This value should be wrapped in double quotes, so we need to unwrap it.
        String ssid = info.getSSID();
        if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }

        promise.resolve(ssid);
    }

    /**
     * Returns the BSSID (basic service set identifier) of the currently connected WiFi network.
     */
    @ReactMethod
    public void getBSSID(final Promise promise) {
        final WifiInfo info = wifi.getConnectionInfo();
        final String bssid = info.getBSSID();
        promise.resolve(bssid.toUpperCase());
    }
    
    @ReactMethod
    public void getSSID(Callback callback) {
        String ssid = this.getWifiSSID();
        callback.invoke(ssid);
    }

    private String getWifiSSID() {
        WifiInfo info = wifiManager.getConnectionInfo();
        String ssid = info.getSSID();

        if (ssid == null || ssid.equalsIgnoreCase("<unknown ssid>")) {
            NetworkInfo nInfo = connectivityManager.getActiveNetworkInfo();
            if (nInfo != null && nInfo.isConnected()) {
                ssid = nInfo.getExtraInfo();
            }
        }

        if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }

        return ssid;
    }

    private WifiConfiguration getExistingNetworkConfig(String ssid) {
        WifiConfiguration existingNetworkConfigForSSID = null;
        List<WifiConfiguration> configList = wifiManager.getConfiguredNetworks();
        String comparableSSID = ('"' + ssid + '"'); // Add quotes because wifiConfig.SSID has them
        if (configList != null) {
            for (WifiConfiguration wifiConfig : configList) {
                if (wifiConfig.SSID.equals(comparableSSID)) {
                    Log.d("IoTWifi", "Found Matching Wifi: "+ wifiConfig.toString());
                    existingNetworkConfigForSSID = wifiConfig;
                    break;

                }
            }
        }
        return existingNetworkConfigForSSID;
    }

    /**
     * Returns the RSSI (received signal strength indicator) of the currently connected WiFi network.
     */
    @ReactMethod
    public void getCurrentSignalStrength(final Promise promise) {
        final int linkSpeed = wifi.getConnectionInfo().getRssi();
        promise.resolve(linkSpeed);
    }

    /**
     * Returns the frequency of the currently connected WiFi network.
     */
    @ReactMethod
    public void getFrequency(final Promise promise) {
        final WifiInfo info = wifi.getConnectionInfo();
        final int frequency = info.getFrequency();
        promise.resolve(frequency);
    }

    /**
     * Returns the IP of the currently connected WiFi network.
     */
    @ReactMethod
    public void getIP(final Promise promise) {
        final WifiInfo info = wifi.getConnectionInfo();
        final String stringIP = longToIP(info.getIpAddress());
        promise.resolve(stringIP);
    }

    /**
     * This method will remove the wifi network configuration.
     * If you are connected to that network, it will disconnect.
     *
     * @param SSID wifi SSID to remove configuration for
     */
    @ReactMethod
    public void isRemoveWifiNetwork(final String SSID, final Promise promise) {
        final List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();
        final String comparableSSID = ('"' + SSID + '"'); //Add quotes because wifiConfig.SSID has them

        for (WifiConfiguration wifiConfig : mWifiConfigList) {
            if (wifiConfig.SSID.equals(comparableSSID)) {
                promise.resolve(wifi.removeNetwork(wifiConfig.networkId));
                wifi.saveConfiguration();
                return;
            }
        }

        promise.resolve(true);
    }

    /**
     * Similar to `loadWifiList` but it forcefully starts a new WiFi scan and only passes the results when the scan is done.
     */
    @ReactMethod
    public void reScanAndLoadWifiList(final Promise promise) {
        final WifiScanResultReceiver wifiScanResultReceiver = new WifiScanResultReceiver(wifi, promise);
        getReactApplicationContext().registerReceiver(wifiScanResultReceiver, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
        wifi.startScan();
    }

    private static String longToIP(int longIp) {
        StringBuilder sb = new StringBuilder();
        String[] strip = new String[4];
        strip[3] = String.valueOf((longIp >>> 24));
        strip[2] = String.valueOf((longIp & 0x00FFFFFF) >>> 16);
        strip[1] = String.valueOf((longIp & 0x0000FFFF) >>> 8);
        strip[0] = String.valueOf((longIp & 0x000000FF));
        sb.append(strip[0]);
        sb.append(".");
        sb.append(strip[1]);
        sb.append(".");
        sb.append(strip[2]);
        sb.append(".");
        sb.append(strip[3]);
        return sb.toString();
    }

    private static String formatWithBackslashes(final String value) {
        return String.format("\"%s\"", value);
    }

    /**
     * @return true if the current sdk is above or equal to Android M
     */
    private static boolean isAndroidLollipopOrLater() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    /**
     * @return true if the current sdk is above or equal to Android Q
     */
    private static boolean isAndroid10OrLater() {
        return false; // TODO: Compatibility with Android 10
        // return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q;
    }
}
