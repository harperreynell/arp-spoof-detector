package com.example.arpspoofdetector

import android.Manifest
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.io.File

class MainActivity : ComponentActivity() {

    private var knownSafeMac: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        requestPermissions(
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_NETWORK_STATE,
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.INTERNET
            ),
            0
        )

        setContent {
            var isSpoofed by remember { mutableStateOf(false) }

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

            Surface(modifier = Modifier.fillMaxSize()) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.Top,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = if (isSpoofed) "⚠️ Possible ARP Spoofing Detected!" else "✅ Network Seems Stable",
                        style = MaterialTheme.typography.headlineSmall
                    )
                }
            }
        }
    }

    private suspend fun checkArpSpoofing(context: Context): Boolean {
        val gatewayIp = getGatewayIp(context)
        Log.d("ARP-Spoof-Detector", "Gateway IP: $gatewayIp")

        if (gatewayIp != null) {
             pingGateway(gatewayIp)

            var gatewayMac = getMacFromIpNeighbor(gatewayIp)
            if (gatewayMac == null) {
                Log.d("ARP-Spoof-Detector", "Trying fallback: /proc/net/arp")
                gatewayMac = getMacFromArpCache(gatewayIp)
            }
            Log.d("ARP-Spoof-Detector", "Gateway MAC: $gatewayMac")
            Log.d("ARP-Spoof-Detector", "Known Safe MAC: $knownSafeMac")

            if (gatewayMac == null) {
                Log.d("ARP-Spoof-Detector", "MAC not found. Could not verify.")
                return false
            }

            if (knownSafeMac != null && gatewayMac != knownSafeMac) {
                Log.w("ARP-Spoof-Detector", "⚠️ MAC mismatch detected — possible spoofing.")
                return true
            }

            if (knownSafeMac == null) {
                knownSafeMac = gatewayMac
                Log.d("ARP-Spoof-Detector", "Initial safe MAC stored: $knownSafeMac")
            }
        }

        return false
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
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
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
}
