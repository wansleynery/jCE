// Importa o utilitário para conversão de tipos e valores
import com.sun.jna.Native
import com.sun.jna.platform.win32.WinNT
import main.Properties
import oshi.software.os.OSProcess

/**
 * Classe principal da aplicação. Responsável por interagir com o usuário via CLI,
 * permitindo a seleção de um processo, a definição do tipo de dado e do valor a
 * pesquisar na memória desse processo e o refinamento sucessivo com novos valores.
 */
class App {
    companion object {
        @JvmStatic
        fun main (args: Array<String>) {
            // Idioma das mensagens padrão (pode ser estendido no futuro)
            val language = "ptBR"
            // Número máximo de endereços a serem mostrados ao usuário em cada etapa
            val maximumShowedAddresses = 50

            // === Processo alvo: pergunta, lista, escolhe ===
            val process: OSProcess = Process.selectProcess(language)
            val processID = process.processID
            val processHandle = Process.open(processID)
                ?: error(
                    Properties.get(
                        "$language.error.processCannotBeOpened",
                        mapOf("pid" to processID.toString())
                    )
                )

            try {
                // Solicita ao usuário o tipo de dado a ser procurado
                print("Tipo de dado (int, float, double, string): ")
                val typeInput = readlnOrNull()?.trim() ?: ""
                val dataType = try {
                    DataParser.parseType(typeInput)
                } catch (e: Exception) {
                    println("Tipo de dado inválido: ${e.message}")
                    return
                }

                // Solicita o valor inicial para a busca
                print("Valor a procurar: ")
                val valueInput = readlnOrNull()?.trim() ?: ""
                if (valueInput.isEmpty()) {
                    println("Valor não pode ser vazio.")
                    return
                }

                val patterns: List<ByteArray> =
                    if (dataType == DataParser.DataType.STRING) {
                        listOf(
                            DataParser.toBytes(DataParser.DataType.STRING, valueInput), // UTF-8
                            DataParser.toBytesUtf16LE(valueInput)                       // UTF-16LE
                        )
                    } else {
                        listOf(DataParser.toBytes(dataType, valueInput))
                    }

                println("Procurando por valores... isso pode levar alguns segundos.")
                // Realiza a primeira varredura na memória do processo
                var addresses = buildList {
                    for (p in patterns) addAll(Memory.searchMemory(processHandle, p))
                }.distinct()
                if (addresses.isEmpty()) {
                    println("Nenhum endereço encontrado para o valor informado.")
                } else {
                    println("Encontrados ${addresses.size} endereços.")
                }

                // Exibe os primeiros endereços ao usuário
                printResults(addresses, processHandle, addresses.size, dataType, maximumShowedAddresses)

                // Loop de refinamento: enquanto o usuário fornecer novos valores, filtra a lista
                while (addresses.isNotEmpty()) {
                    print("Novo valor para refinar (ENTER para encerrar): ")
                    val newValue = readlnOrNull()?.trim() ?: ""
                    if (newValue.isEmpty()) {
                        // Encerra se o usuário não quiser refinar mais
                        break
                    }

                    val newPatterns =
                        if (dataType == DataParser.DataType.STRING) {
                            listOf(
                                DataParser.toBytes(DataParser.DataType.STRING, newValue),
                                DataParser.toBytesUtf16LE(newValue)
                            )
                        } else {
                            listOf(DataParser.toBytes(dataType, newValue))
                        }
                    // Filtra apenas endereços cujo conteúdo corresponde ao novo valor
                    addresses = addresses.filter { addr ->
                        newPatterns.any { np ->
                            val data = Memory.read(processHandle, addr, np.size)
                            data != null && data.contentEquals(np)
                        }
                    }
                    println("Restam ${addresses.size} endereços.")
                    if (addresses.isEmpty()) {
                        break
                    }
                    // Mostra novamente os primeiros N endereços após o filtro
                    printResults(addresses, processHandle, newPatterns.size, dataType, maximumShowedAddresses)
                }

            } finally {
                // Garante fechar o handle sempre
                Memory.close(processHandle)
            }
        }
    }
}

/**
 * Exibe uma lista de endereços e seus respectivos valores ao usuário. A listagem é
 * limitada pelo parâmetro `maxShow` para evitar inundar a saída com muitos resultados.
 * Cada linha apresenta o valor lido interpretado de acordo com `dataType` seguido
 * pelo endereço em hexadecimal. Se houver mais resultados do que o limite, são
 * mostrados apenas os primeiros e uma reticência é impressa ao final.
 *
 * @param addresses Lista de endereços de memória encontrados.
 * @param handle Handle do processo para ler os valores.
 * @param size Número de bytes a ler em cada endereço (tamanho do padrão).
 * @param dataType Tipo dos dados, utilizado para formatar o valor para exibição.
 * @param maxShow Máximo de endereços a serem exibidos.
 */
fun printResults(
    addresses: List<Long>,
    handle: WinNT.HANDLE,
    size: Int,
    dataType: DataParser.DataType,
    maxShow: Int
) {
    val count = if (addresses.size > maxShow) maxShow else addresses.size
    for (i in 0 until count) {

        val addr = addresses[i]

        // Calcula a representação hexadecimal do endereço, sem prefixo
        val addrHex = addr.toString(16).uppercase().padStart(Native.POINTER_SIZE * 2, '0')

        val valueStr =
            if (dataType == DataParser.DataType.STRING) {
                val peek = Memory.read(handle, addr, 64) ?: ByteArray(0)

                // tenta UTF-8 (corta no \0)
                val sUtf8 = runCatching {
                    val raw = String(peek, Charsets.UTF_8)
                    val cut = raw.indexOf('\u0000')
                    if (cut >= 0) raw.take(cut) else raw
                }.getOrNull()

                // tenta UTF-16LE (corta no \0)
                val sUtf16 = runCatching {
                    val raw = String(peek, Charsets.UTF_16LE)
                    val cut = raw.indexOf('\u0000')
                    if (cut >= 0) raw.take(cut) else raw
                }.getOrNull()

                // escolhe a mais “imprimível”
                listOfNotNull(sUtf16, sUtf8).maxByOrNull { s ->
                    s.count { ch -> !ch.isISOControl() }
                } ?: ""
            } else {
                val bytes = Memory.read(handle, addr, size)
                if (bytes != null) {
                    runCatching { DataParser.fromBytes(dataType, bytes) }
                        .getOrElse { bytes.joinToString(" ") { b -> "%02X".format(b) } }
                } else ""
            }

        // Imprime linha formatada (UI.printLine adiciona prefixo '0x' ao endereço)
        println(UI.printLine(valueStr, addrHex))
    }
    if (addresses.size > maxShow) {
        println("...")
    }
}