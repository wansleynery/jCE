import UI.toPrettyName
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import oshi.SystemInfo
import oshi.software.os.OSProcess
import oshi.software.os.OperatingSystem
import java.io.File

object Process {

    sealed class ResolveResult {
        data class Single (val process: OSProcess) : ResolveResult ()
        data class Multiple (val matches: List <Pair <String, OSProcess>>) : ResolveResult ()
        data object NotFound : ResolveResult ()
    }

    fun resolve (
        identifier: String
    ): ResolveResult {

        // PID numérico?
        identifier.toIntOrNull ()?.let { pid ->

            open (pid)?.let {

                // handle ok: fecha handle de teste e devolve o OSProcess correspondente
                Memory.close (it)

                val hit = findBy ("^$pid$").firstOrNull ()?.second
                if (hit != null) return ResolveResult.Single (hit)

            }

            return ResolveResult.NotFound

        }

        // Regex/nome
        val matches = findBy (identifier)

        return when (matches.size) {
            0  -> ResolveResult.NotFound
            1  -> ResolveResult.Single (matches.first ().second)
            else -> ResolveResult.Multiple (matches)
        }

    }


    // Abre o processo com permissão de leitura (PROCESS_VM_READ)
    fun open (
        pid: Int
    ): WinNT.HANDLE? {

        val desired =
            WinNT.PROCESS_QUERY_INFORMATION or
            WinNT.PROCESS_VM_READ           or
            WinNT.PROCESS_VM_WRITE          or
            WinNT.PROCESS_VM_OPERATION

        val handle = Kernel32.INSTANCE.OpenProcess (desired, false, pid)

        return (
            if (handle != null && WinNT.INVALID_HANDLE_VALUE != handle)
                handle
            else
                null
        )
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
                val pretty  = exeName.toPrettyName ().uppercase ()

                Pair ("$pid;$exeName;$pretty", process)
            }
    }

}