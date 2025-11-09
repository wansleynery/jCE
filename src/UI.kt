import com.sun.jna.Native
import com.sun.jna.platform.win32.WinNT
import java.util.Locale

object UI {

    fun printLine (
        left: String,
        value: String,
        width: Int = 30
    ): String {
        val right = "0x" + value.uppercase ().padStart (Native.POINTER_SIZE * 2, '0')
        val dots = ".".repeat ((width - left.length - right.length).coerceAtLeast (1))
        return "$left $dots $right"
    }

    /**
     * Exibe uma lista de endereços de memória e seus respectivos valores ao usuário.
     * A listagem é limitada pelo parâmetro `maxShow` para evitar inundar a saída com
     * muitos resultados. Cada linha apresenta o valor lido interpretado de acordo
     * com o tipo de dado (`dataType`) seguido pelo endereço em hexadecimal.
     * Se houver mais resultados do que o limite, são mostrados apenas os primeiros
     * e uma reticência é impressa ao final.
     *
     * @param addresses Lista de endereços de memória encontrados.
     * @param handle Handle do processo usado para ler os valores.
     * @param bytesToRead Número de bytes a ler em cada endereço (tamanho do padrão original).
     * @param dataType Tipo dos dados, utilizado para formatar o valor para exibição.
     * @param maxShow Quantidade máxima de endereços a serem exibidos ao usuário.
     */
    fun printResults (
        addresses: List <Long>,
        handle: WinNT.HANDLE,
        bytesToRead: Int,
        dataType: DataParser.DataType,
        maxShow: Int
    ) {

        val count = if (addresses.size > maxShow) maxShow else addresses.size

        for (i in 0 until count) {

            val addr = addresses [i]

            // Calcula a representação hexadecimal do endereço, sem prefixo
            val addrHex = addr.toString(16).uppercase().padStart(Native.POINTER_SIZE * 2, '0')

            // Lê os bytes da memória para exibir o valor em formato humano.
            // Para strings, fazemos uma leitura mais longa (64 bytes) e tentamos decodificar
            // tanto em UTF‑8 quanto em UTF‑16LE, escolhendo a mais “imprimível”. Para
            // outros tipos, lemos exatamente o tamanho do padrão informado (size) e
            // decodificamos via DataParser.
            val valueStr = if (dataType == DataParser.DataType.STRING) {

                val peek = Memory.read (handle, addr, 64) ?: ByteArray (0)

                // tenta UTF-8 (corta no \0)
                val sUtf8 = runCatching {
                    val raw = String (peek, Charsets.UTF_8)
                    val cut = raw.indexOf ('\u0000')
                    if (cut >= 0) raw.take (cut) else raw
                }.getOrNull ()

                // tenta UTF-16LE (corta no \0)
                val sUtf16 = runCatching {
                    val raw = String (peek, Charsets.UTF_16LE)
                    val cut = raw.indexOf ('\u0000')
                    if (cut >= 0) raw.take (cut) else raw
                }.getOrNull ()

                listOfNotNull (sUtf16, sUtf8).maxByOrNull { s ->
                    s.count { ch -> !ch.isISOControl () }
                } ?: ""

            } else {
                val bytes = Memory.read (handle, addr, bytesToRead)
                if (bytes != null) {
                    runCatching { DataParser.fromBytes (dataType, bytes) }
                        .getOrElse { bytes.joinToString (" ") { b -> "%02X".format (b) } }
                } else {
                    ""
                }
            }

            // Imprime linha formatada (UI.printLine adiciona prefixo '0x' ao endereço)
            println (printLine (valueStr, addrHex))
        }

        if (addresses.size > maxShow) {
            println ("...")
        }
    }

    /**
     * Heurística de "nome bonito": remove extensão, troca separadores por espaço e capitaliza.
     * Ex: "chrome.exe" -> "Chrome", "visual_studio_code" -> "Visual Studio Code"
     */
    fun String.toPrettyName (): String {
        val base = this.removeSuffix (".exe")
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
            .ifBlank { this }
    }

}