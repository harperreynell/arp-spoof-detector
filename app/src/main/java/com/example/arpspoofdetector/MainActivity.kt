package com.example.arpspoofdetector

import android.Manifest
import android.R
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.RingtoneManager
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.annotation.RequiresPermission
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.example.arpspoofdetector.ui.theme.ArpSpoofDetectorTheme
import com.example.arpspoofdetector.ui.theme.JetBrainsMono
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.net.InetAddress

class MainActivity : ComponentActivity() {

    private var knownSafeMac: String? = null
    private var message: String = ""
    private var color: Color = Color.Green

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    @androidx.annotation.RequiresPermission(android.Manifest.permission.POST_NOTIFICATIONS)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        requestPermissions(
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_NETWORK_STATE,
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.INTERNET,
                Manifest.permission.POST_NOTIFICATIONS
            ),
            0
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(Intent(this, ArpMonitorService::class.java))
        } else {
            startService(Intent(this, ArpMonitorService::class.java))
        }
        createNotificationChannel()

        setContent {
            var isSpoofed by remember { mutableStateOf(false) }
            ArpSpoofDetectorTheme (darkTheme = true) {
                LaunchedEffect(Unit) {
                    while (true) {
                        try {
                            Log.d("ARP-Spoof-Detector", "Checking for ARP spoofing...")
                            isSpoofed = checkArpSpoofing(this@MainActivity)
                            Log.d("ARP-Spoof-Detector", "ARP spoofing status: $isSpoofed")
                        } catch (e: Exception) {
                            Log.e("ARP-Spoof-Detector", "Error: ${e.message}")
                            isSpoofed = false
                        }
                        delay(5000)
                    }
                }
                if(isSpoofed) showSpoofingNotification()
                if (isSpoofed) {
                    message = "⚠️ Possible ARP Spoofing Detected!"
                    color = Color.Red
                } else {
                    message = "✅ Network Seems Stable"
                    color = Color.Green
                }
                Surface(modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    )  {
                        Text(
                            fontFamily = JetBrainsMono,
                            fontSize = 15.sp,
                            text = message,
                            color = color,
                            style = MaterialTheme.typography.headlineSmall,
                        )
                    }
                }
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "ARP_ALERTS",
                "ARP Spoof Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications about suspicions network activity"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    @RequiresPermission(Manifest.permission.POST_NOTIFICATIONS)
    private fun showSpoofingNotification() {
        val builder = NotificationCompat.Builder(this, "ARP_ALERTS")
            .setSmallIcon(R.drawable.stat_sys_warning)
            .setContentTitle("🚨 Possible ARP Spoofing Detected!")
            .setContentText("Somebody is trying to spoof your traffic.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)

        NotificationManagerCompat.from(this).notify(1002, builder.build())
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 101) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.d("Permissions", "Permissions allowed")
            } else {
                Log.d("Permissions", "User denied notifications permissions")
            }
        }
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

    fun getArpTableFromIpNeigh(): Map<String, String> {
        val arpTable = mutableMapOf<String, String>()

        try {
            val process = Runtime.getRuntime().exec("ip neigh")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?

            while (reader.readLine().also { line = it } != null) {
                val parts = line!!.split("\\s+".toRegex())
                if (parts.size >= 5) {
                    val ip = parts[0]
                    val mac = parts[4]
                    arpTable[ip] = mac
                }
            }

            reader.close()
        } catch (e: IOException) {
            e.printStackTrace()
        }

        return arpTable
    }

    private suspend fun checkArpSpoofing(context: Context): Boolean {
        val gatewayIp = getGatewayIp(context)
        val bssid = getCurrentWifiId(context)

        if (gatewayIp != null && bssid != null) {
            pingGateway(gatewayIp)

            val arpTable = getArpTableFromIpNeigh()
            Log.d("ARP", arpTable.toString())
            var gatewayMac = arpTable[gatewayIp]

            if (gatewayMac == null) {
                Log.d("ARP", "Couldn't find MAC address from ip neigh, fallback to /proc/net/arp")
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
            } else {
                Log.e("ARP", "Couldn't get gateway MAC.")
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
