package org.wolpmessenger.devicetrust.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.wolpmessenger.devicetrust.api.PrecheckResult
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val ctx = LocalContext.current
            val scheme = if (isSystemInDarkTheme()) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
            MaterialTheme(colorScheme = scheme) { SampleScreen() }
        }
    }
}

private val Good = Color(0xFF2E7D32)
private val Warn = Color(0xFFB26A00)
private val Bad = Color(0xFFC62828)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SampleScreen() {
    val context = LocalContext.current
    val diag = remember { Diagnostics(context.applicationContext) }
    val scope = rememberCoroutineScope()

    var busy by remember { mutableStateOf<String?>(null) }
    var precheck by remember { mutableStateOf<PrecheckResult?>(null) }
    val attestation = remember { mutableStateListOf<AttestationProbe>() }
    val keyBench = remember { mutableStateListOf<KeyBench>() }
    var vaultBench by remember { mutableStateOf<VaultBench?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val hasStrongBox = remember { DeviceFacts.hasStrongBox(context) }

    fun run(label: String, block: suspend () -> Unit) {
        if (busy != null) return
        busy = label
        error = null
        scope.launch {
            try {
                block()
            } catch (e: Exception) {
                error = "${e.javaClass.simpleName}: ${e.message}"
            } finally {
                busy = null
            }
        }
    }

    suspend fun <T> bg(block: () -> T): T = withContext(Dispatchers.Default) { block() }

    LaunchedEffect(Unit) { run("Precheck") { precheck = bg { diag.precheck() } } }

    Scaffold(topBar = { TopAppBar(title = { Text("Wolp Device Trust") }) }) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { DeviceCard() }
            item {
                PrecheckCard(precheck) { run("Precheck") { precheck = bg { diag.precheck() } } }
            }
            item {
                AttestationCard(attestation, hasStrongBox, enabled = busy == null) {
                    run("Attestation") {
                        attestation.clear()
                        attestation += bg { diag.attest(strongBox = false) }
                        if (hasStrongBox) attestation += bg { diag.attest(strongBox = true) }
                    }
                }
            }
            item {
                BenchCard(keyBench, vaultBench, hasStrongBox, enabled = busy == null) {
                    run("Measuring") {
                        keyBench.clear(); vaultBench = null
                        keyBench += bg { diag.keyBench(false) { p -> busy = "TEE: $p" } }
                        if (hasStrongBox) keyBench += bg { diag.keyBench(true) { p -> busy = "StrongBox: $p" } }
                        vaultBench = bg { diag.vaultBench { p -> busy = "Vault: $p" } }
                    }
                }
            }
            item {
                ShareCard(enabled = busy == null) {
                    run("Exporting test vectors") {
                        val vectors = bg { TestVectorExporter(context.applicationContext).export() }
                        Report.share(context, Report.build(context, precheck, attestation, keyBench, vaultBench, vectors))
                    }
                }
            }
            busy?.let { item { BusyRow(it) } }
            error?.let { item { Text(it, color = Bad, style = MaterialTheme.typography.bodySmall) } }
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            content()
        }
    }
}

@Composable
private fun KeyValue(key: String, value: String, valueColor: Color = Color.Unspecified) {
    Row(Modifier.fillMaxWidth()) {
        Text(key, Modifier.width(130.dp), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = valueColor)
    }
}

@Composable
private fun Badge(text: String, color: Color) {
    Text(
        text,
        modifier = Modifier.clip(RoundedCornerShape(50)).background(color.copy(alpha = 0.15f)).padding(horizontal = 10.dp, vertical = 3.dp),
        color = color, fontWeight = FontWeight.SemiBold, fontSize = 13.sp,
    )
}

@Composable
private fun DeviceCard() {
    val context = LocalContext.current
    Section("Device") { DeviceFacts.rows(context).forEach { (k, v) -> KeyValue(k, v) } }
}

@Composable
private fun PrecheckCard(result: PrecheckResult?, onRun: () -> Unit) {
    Section("Precheck (S2 §6.1)") {
        when (result) {
            null -> Text("running…")
            is PrecheckResult.Supported -> {
                Badge("Supported", Good)
                KeyValue("Keystore", result.info.keystoreLevel.name, Good)
                if (result.reports.isNotEmpty()) KeyValue("Reports", result.reports.joinToString { it.id }, Warn)
            }
            is PrecheckResult.Unsupported -> {
                Badge("Unsupported", Bad)
                KeyValue("Reasons", result.reasons.joinToString(), Bad)
                result.info?.let { KeyValue("Keystore", it.keystoreLevel.name, if (it.keystoreLevel.isHardwareConfirmed) Good else Bad) }
            }
            is PrecheckResult.Compromised -> {
                Badge("Compromised", Bad)
                KeyValue("Findings", result.report.findings.joinToString { it.id }, Bad)
            }
        }
        TextButton(onClick = onRun) { Text("Run again") }
    }
}

@Composable
private fun AttestationCard(probes: List<AttestationProbe>, hasStrongBox: Boolean, enabled: Boolean, onRun: () -> Unit) {
    Section("Key attestation") {
        Text(
            if (hasStrongBox) "Generates an attested EC P-256 key in TEE and in StrongBox." else "Generates an attested EC P-256 key in TEE (no StrongBox declared).",
            style = MaterialTheme.typography.bodySmall,
        )
        probes.forEach { p ->
            HorizontalDivider()
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (p.requestedStrongBox) "StrongBox" else "TEE", fontWeight = FontWeight.SemiBold)
                Badge(p.level, if (p.hardwareConfirmed) Good else Bad)
                if (p.strongBoxFallback) Badge("fallback", Warn)
            }
            p.error?.let { Text(it, color = Bad, style = MaterialTheme.typography.bodySmall) }
            if (p.chain.isNotEmpty()) KeyValue("Chain", "${p.chain.size} certs · ${p.chainType}")
            p.chain.forEachIndexed { i, c ->
                Column {
                    Text("${i + 1}. ${shortName(c.subject)}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, fontWeight = FontWeight.Medium)
                    Text("    issued by ${shortName(c.issuer)}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Button(onClick = onRun, enabled = enabled) { Text(if (probes.isEmpty()) "Generate" else "Generate again") }
    }
}

private fun shortName(dn: String): String =
    dn.split(',').map { it.trim() }.let { parts -> parts.firstOrNull { it.startsWith("CN=") } ?: parts.firstOrNull() ?: dn }.removePrefix("CN=")

@Composable
private fun BenchCard(keys: List<KeyBench>, vault: VaultBench?, hasStrongBox: Boolean, enabled: Boolean, onRun: () -> Unit) {
    Section("Measurements (S2 §3, §9)") {
        Text("Signature latency is the private-key cost of every mTLS handshake; parallel = WebView cold start.", style = MaterialTheme.typography.bodySmall)
        keys.forEach { k ->
            HorizontalDivider()
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (k.requestedStrongBox) "StrongBox" else "TEE", fontWeight = FontWeight.SemiBold)
                k.level?.let { Badge(it, if (it == "STRONGBOX" || it == "TRUSTED_ENVIRONMENT") Good else Bad) }
            }
            k.note?.let { Text(it, color = Warn, style = MaterialTheme.typography.bodySmall) }
            k.keygen?.let { KeyValue("Keygen", "p50 ${ms(it.p50)} · max ${ms(it.max)}") }
            k.sign?.let { KeyValue("Sign", "p50 ${ms(it.p50)} · p95 ${ms(it.p95)}") }
            k.parallelSign?.let { KeyValue("Parallel ×$PARALLEL", "p95 ${ms(it.p95)} · wall ${ms(k.parallelWallMs ?: 0.0)}") }
        }
        val signs = keys.mapNotNull { k -> k.sign?.let { (if (k.requestedStrongBox) "StrongBox" else "TEE") to it.p95 } }
        if (signs.size > 1) SignBars(signs)
        vault?.let { v ->
            HorizontalDivider()
            Text("Vault", fontWeight = FontWeight.SemiBold)
            TargetRow("DEK unwrap p95", v.dekUnwrap.p95, DEK_TARGET_MS)
            TargetRow("wrap 4 KiB p95", v.wrap4k.p95, VAULT_OP_TARGET_MS)
            TargetRow("unwrap 4 KiB p95", v.unwrap4k.p95, VAULT_OP_TARGET_MS)
        }
        Button(onClick = onRun, enabled = enabled) { Text(if (keys.isEmpty()) "Run (~${if (hasStrongBox) 60 else 20} s)" else "Run again") }
    }
}

@Composable
private fun SignBars(values: List<Pair<String, Double>>) {
    val max = values.maxOf { it.second }.coerceAtLeast(0.001)
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Sign p95, ms", style = MaterialTheme.typography.labelMedium)
        values.forEach { (label, v) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(label, Modifier.width(80.dp), fontSize = 12.sp)
                Box(Modifier.weight(1f).height(14.dp)) {
                    Box(
                        Modifier.fillMaxHeight().fillMaxWidth((v / max).toFloat())
                            .clip(RoundedCornerShape(4.dp)).background(MaterialTheme.colorScheme.primary),
                    )
                }
                Text(ms(v), Modifier.width(64.dp).padding(start = 6.dp), fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun TargetRow(label: String, value: Double, target: Double) {
    val ok = value <= target
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        Text(ms(value))
        Badge(if (ok) "≤ ${ms(target)}" else "> ${ms(target)}", if (ok) Good else Bad)
    }
}

@Composable
private fun ShareCard(enabled: Boolean, onShare: () -> Unit) {
    Section("Report") {
        Text(
            "Exports fresh attestation test vectors (with CSR) and everything above into one JSON, then opens the share sheet — send it to yourself or to the team.",
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedButton(onClick = onShare, enabled = enabled) { Text("Share report") }
    }
}

@Composable
private fun BusyRow(label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
    Spacer(Modifier.height(8.dp))
}

private fun ms(v: Double): String = if (v < 10) String.format(Locale.US, "%.2f ms", v) else String.format(Locale.US, "%.0f ms", v)
