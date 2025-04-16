package com.example.arpspoofdetector

import android.Manifest
import android.R
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.annotation.RequiresPermission
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress

class ArpMonitorService : LifecycleService() {

    @RequiresApi(Build.VERSION_CODES.O)
    @androidx.annotation.RequiresPermission(android.Manifest.permission.POST_NOTIFICATIONS)
    override fun onCreate() {
        super.onCreate()
        startForegroundService()

        lifecycleScope.launch {
            while (true) {
                val isSpoofed = checkArpSpoofing(this@ArpMonitorService)
                if (isSpoofed) {
                    showSpoofingNotification()
                }
                delay(5000)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun startForegroundService() {
        val channelId = "ARP_MONITOR_CHANNEL"
        val channel = NotificationChannel(
            channelId,
            "ARP Monitor",
            NotificationManager.IMPORTANCE_LOW
        )

        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)

        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("ARP Spoofing Monitor")
            .setContentText("Network scan is active")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .build()

        startForeground(1, notification)
    }

    @RequiresPermission(Manifest.permission.POST_NOTIFICATIONS)
    private fun showSpoofingNotification() {
        val builder = NotificationCompat.Builder(this, "ARP_ALERTS")
            .setSmallIcon(R.drawable.stat_sys_warning)
            .setContentTitle("🚨 ARP Spoofing Detected")
            .setContentText("Gateway MAC has been changed.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)

        NotificationManagerCompat.from(this).notify(1002, builder.build())
    }

    private suspend fun getMacFromIpNeighbor(ip: String): String? = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec("ip neighbor")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val lines = reader.readLines()
            reader.close()

            for (line in lines) {
                if (line.contains(ip)) {
                    val tokens = line.split("\\s+".toRegex())
                    val macIndex = tokens.indexOf("lladdr")
                    if (macIndex != -1 && macIndex + 1 < tokens.size) {
                        return@withContext tokens[macIndex + 1]
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return@withContext null
    }

    private fun getGatewayIp(context: Context): String? {
        val wifiManager =
            context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val dhcpInfo = wifiManager.dhcpInfo
        val gatewayInt = dhcpInfo.gateway
        return InetAddress.getByAddress(
            byteArrayOf(
                (gatewayInt and 0xFF).toByte(),
                ((gatewayInt shr 8) and 0xFF).toByte(),
                ((gatewayInt shr 16) and 0xFF).toByte(),
                ((gatewayInt shr 24) and 0xFF).toByte()
            )
        ).hostAddress
    }

    private suspend fun pingGateway(ip: String) = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", ip))
            process.waitFor()
            Log.d("ARP-Spoof-Detector", "Ping to $ip completed.")
        } catch (e: Exception) {
            Log.e("ARP-Spoof-Detector", "Ping error: ${e.message}")
        }
    }

    private fun getMacFromArpCache(ip: String): String? {
        repeat(3) { attempt ->
            val mac = readArpFile(ip)
            if (mac != null) return mac
            Thread.sleep(300)
        }
        return null
    }

    private fun readArpFile(ip: String): String? {
        return try {
            val arpFile = File("/proc/net/arp")
            if (!arpFile.exists()) return null

            arpFile.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val parts = line.split("\\s+".toRegex())
                    if (parts.size >= 4 && parts[0] == ip) {
                        val mac = parts[3]
                        if (mac.matches(Regex("..:..:..:..:..:.."))) {
                            return@useLines mac
                        }
                    }
                }
                null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private suspend fun checkArpSpoofing(context: Context): Boolean {
        val gatewayIp = getGatewayIp(context)
        val bssid = getCurrentWifiId(context)

        if (gatewayIp != null && bssid != null) {
            pingGateway(gatewayIp)

            var gatewayMac = getMacFromIpNeighbor(gatewayIp)
            if (gatewayMac == null) {
                gatewayMac = getMacFromArpCache(gatewayIp)
            }

            if (gatewayMac != null) {
                val knownMac = getKnownMacForNetwork(context, bssid)

                if (knownMac == null) {
                    saveKnownMacForNetwork(context, bssid, gatewayMac)
                    Log.d("ARP", "Stored safe MAC for new network: $gatewayMac")
                    return false
                }

                if (knownMac != gatewayMac) {
                    Log.w("ARP", "⚠️ MAC mismatch for network $bssid — possible spoofing!")
                    return true
                }
            }
        }

        return false
    }


    private fun getCurrentWifiId(context: Context): String? {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = wifiManager.connectionInfo
        return if (wifiInfo != null && wifiInfo.ssid != "<unknown ssid>") {
            wifiInfo.bssid
        } else {
            null
        }
    }

    private fun saveKnownMacForNetwork(context: Context, bssid: String, mac: String) {
        val prefs = context.getSharedPreferences("safe_macs", Context.MODE_PRIVATE)
        prefs.edit().putString(bssid, mac).apply()
    }

    private fun getKnownMacForNetwork(context: Context, bssid: String): String? {
        val prefs = context.getSharedPreferences("safe_macs", Context.MODE_PRIVATE)
        return prefs.getString(bssid, null)
    }
}
