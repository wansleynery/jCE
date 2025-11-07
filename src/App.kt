import com.sun.jna.Native
import main.Properties
import oshi.software.os.OSProcess

class App {
    companion object {
        @JvmStatic
        fun main (args: Array<String>) {

            val language = "ptBR"
            val maximumShowedPointers = 50
            val previewBytes = 32

            // === Processo alvo: pergunta, lista, escolhe ===
            val process: OSProcess = Process.selectProcess (language)
            val processID = process.processID
            val processHandle = Process.open (processID)
                ?: error (
                    Properties.get (
                        "$language.error.processCannotBeOpened",
                        mapOf ("pid" to processID.toString ())
                    )
                )

            try {
                val pointerList = Memory.listPointers (processHandle, 50)
                if (pointerList.isEmpty ()) {
                    error (Properties.get ("$language.error.processCannotBeOpened"))
                }

                var pointerCount = 0
                val filteredCountPointers = if (pointerList.size > maximumShowedPointers) {
                    pointerList.take (maximumShowedPointers)
                } else {
                    pointerList
                }

                // Se preferir mostrar também o valor apontado, faça a leitura aqui.
                for (address in filteredCountPointers) {

                    // 1) Tenta ler um "preview" maior para detectar string (ex.: até 32 bytes)
                    val valueBytes = Memory.read (processHandle, address, Native.POINTER_SIZE) ?: continue
                    val valueAsLong = MemSample (valueBytes).asU64 ()

                    // mantém só ponteiros cujo VALOR também parece outro ponteiro legível
                    if (valueAsLong < 0x10000L || !Memory.isReadableAddress (processHandle, valueAsLong)) continue

                    // 2) lê um "preview" maior onde o ponteiro aponta (para tentar decodificar texto)
                    val preview = Memory.read(processHandle, valueAsLong, previewBytes) ?: continue

                    // 3) tenta extrair string ASCII imprimível
                    val text = preview
                        .takeWhile { it != 0.toByte() }           // até \0
                        .map { (it.toInt() and 0xFF).toChar() }
                        .joinToString("")

                    val zeroAt = preview.indexOf (0)
                    val len    = if (zeroAt >= 0) zeroAt else preview.size
                    val utf8   = String (preview, 0, len, Charsets.UTF_8)
                    val printable = utf8.filter { !it.isISOControl () }

                    // 4) aceita como “string plausível” se tiver pelo menos 1 char
                    //    e pelo menos 70% dos chars forem imprimíveis
                    val looksLikeString = printable.isNotEmpty () && printable.length >= (text.length * 0.7).toInt ()

                    if (!looksLikeString) continue

                    // 2) Formata o endereço (sempre em hex)
                    val addrHex = "0x" + address.toString (16)
                                                .uppercase ()
                                                .padStart (Native.POINTER_SIZE * 2, '0')

                    pointerCount++ // Contador de ponteiros processados

                    if (pointerCount == maximumShowedPointers) {
                        println ("...")
                        break
                    }
                    else println (UI.printLine (printable, addrHex))

                }

            } finally {
                // garante fechar o handle sempre
                Memory.close (processHandle)
            }
        }
    }
}
