import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import main.Properties
import oshi.SystemInfo
import oshi.software.os.OSProcess
import oshi.software.os.OperatingSystem
import java.io.File
import java.util.Locale

object Process {

    fun selectProcess (
        language: String
    ): OSProcess {

        while (true) {

            print (Properties.get ("$language.prompt.enterProcess")) // exibe dica
            val input = readlnOrNull ()?.trim ().orEmpty ()
            if (input.isEmpty ()) {
                println (Properties.get ("$language.info.emptyInput"))
                continue
            }

            // Se for PID numérico, trata direto
            input.toIntOrNull ()?.let { pid ->
                open (pid)?.let { handle ->

                    // Fecha o handle de teste e pega o OSProcess via listagem
                    Memory.close (handle)

                    val hit = findBy ("^$pid$").firstOrNull ()?.second
                    if (hit != null) {
                        println (
                            Properties.get (
                                "$language.info.selected",
                                mapOf ("pid" to hit.processID.toString (), "name" to (hit.name ?: ""))
                            )
                        )
                        return hit
                    }

                }

                println (
                    Properties.get (
                        "$language.error.processNotFound",
                        mapOf ("processName" to input)
                    )
                )
                return@let
            }

            // Nome/regex: usa findBy com regex
            val matches = findBy(input)
            if (matches.isEmpty()) {
                println (
                    Properties.get (
                        "$language.error.processNotFound",
                        mapOf ("processName" to input)
                    )
                )
                continue
            }

            if (matches.size == 1) {
                val only = matches.first ().second
                println (
                    Properties.get (
                        "$language.info.selected",
                        mapOf (
                            "pid" to only.processID.toString (),
                            "name" to (only.name ?: "")
                        )
                    )
                )
                return only
            }

            // Lista múltiplos resultados
            println (
                Properties.get (
                    "$language.info.foundN",
                    mapOf (
                        "count" to matches.size.toString (),
                        "query" to input
                    )
                )
            )

            matches.forEachIndexed { idx, pair ->
                val meta = pair.first.split (';') // "pid;exe;Pretty"
                val pid  = meta.getOrNull (0) ?: "????"
                val exe  = meta.getOrNull (1) ?: "unknown.exe"
                val nice = meta.getOrNull (2) ?: exe
                println ("  [$idx] PID $pid  -  $nice  ($exe)")
            }

            while (true) {
                print (
                    Properties.get (
                        "$language.prompt.chooseIndex",
                        mapOf (
                            "min" to "0",
                            "max" to matches.lastIndex.toString ()
                        )
                    )
                )

                val pick = readlnOrNull ()?.trim ().orEmpty ()
                if (pick.isEmpty ()) break // cancela e volta a perguntar o termo

                val i = pick.toIntOrNull()
                if (i != null && i in matches.indices) {
                    val chosen = matches[i].second
                    println (
                        Properties.get (
                            "$language.info.selected",
                            mapOf (
                                "pid" to chosen.processID.toString (),
                                "name" to (chosen.name ?: "")
                            )
                        )
                    )
                    return chosen
                }

                println (Properties.get ("$language.error.invalidIndex"))
            }
        }
    }

    // Abre o processo com permissão de leitura (PROCESS_VM_READ)
    fun open (
        pid: Int
    ): WinNT.HANDLE? {
        val dwDesiredAccess = Kernel32.PROCESS_VM_READ or Kernel32.PROCESS_QUERY_INFORMATION
        val handle = Kernel32.INSTANCE.OpenProcess (dwDesiredAccess, false, pid)
        return if (handle != null && !WinNT.INVALID_HANDLE_VALUE.equals (handle)) handle else null
    }

    fun findBy (
        identifier: String
    ): List <Pair <String, OSProcess>> {
        val processes = list ()

        // Tente tratar como regex (case-insensitive). Se inválido, cai no contains ignoreCase
        val regex: Regex? = try {
            Regex(identifier, RegexOption.IGNORE_CASE)
        } catch (_: Exception) {
            null
        }

        return if (regex != null) {
            processes.filter { pair ->
                val meta = pair.first.split (';') // "PID;exe;Pretty"
                val pid  = meta.getOrNull (0) ?: ""
                val exe  = meta.getOrNull (1) ?: ""
                val nice = meta.getOrNull (2) ?: exe

                // casa em qualquer um dos campos
                   regex.containsMatchIn (pid)
                || regex.containsMatchIn (exe)
                || regex.containsMatchIn (nice)
            }
        } else {
            processes.filter { it.first.contains (identifier, ignoreCase = true) }
        }
    }

    /**
     * Lista até `maxSize` processos no formato:
     * PID - executavel - Nome Bonito
     *
     * Usa OSHI (multiplataforma). Ordena por uso de CPU, desc.
     */
    private fun list (): List <Pair <String, OSProcess>> {

        val sistemInformation = SystemInfo ()
        val operatingSystem   = sistemInformation.operatingSystem

        // Ordena por CPU para ficar interessante na tela
        val processes = operatingSystem.getProcesses (
            null,                                    // todos
            OperatingSystem.ProcessSorting.CPU_DESC, // por CPU desc
            -1
        )

        return processes
            .filter { process ->
                (!process.name.isNullOrEmpty () && !process.path.isNullOrEmpty ()) && 0 != process.processID
            }
            .map { process ->
                val pid     = process.processID
                val exePath = process.path ?: ""
                val exeName = (
                    try { File (exePath).name } catch (_: Exception) { "" }
                ).ifBlank { process.name ?: "unknown" }
                val pretty  = toPrettyName (exeName).uppercase ()

                Pair ("$pid;$exeName;$pretty", process)
            }
    }

    /**
     * Heurística de "nome bonito": remove extensão, troca separadores por espaço e capitaliza.
     * Ex: "chrome.exe" -> "Chrome", "visual_studio_code" -> "Visual Studio Code"
     */
    private fun toPrettyName (exe: String): String {
            val base = exe.removeSuffix (".exe")
                .removeSuffix (".bin")
                .removeSuffix (".app")
                .removeSuffix (".out")

            return base
                .replace (Regex ("[_\\-]+"), " ")
                .trim ()
                .lowercase (Locale.getDefault ())
                .split (' ')
                .filter { it.isNotBlank () }
                .joinToString (" ") { it.replaceFirstChar { c -> c.titlecase (Locale.getDefault ()) } }
                .ifBlank { exe }
        }

}